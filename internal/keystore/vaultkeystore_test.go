// External test package: keystoretest imports internal/keystore itself,
// so a package-internal (package keystore) test file importing
// keystoretest would create an import cycle in the test build. See
// internal/store/storetest for the same pattern applied where it doesn't
// need this workaround (sqlite/postgres are sibling packages of store,
// not store itself).
package keystore_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prampec/trustmate/internal/keystore"
	"github.com/prampec/trustmate/internal/keystore/keystoretest"
)

// fakeTransit is a minimal in-process stand-in for Vault's Transit
// secrets engine HTTP API -- just enough of the real wire protocol
// (create/read/sign under /v1/<mount>/...) for VaultKeyStore's client
// code to be exercised against real HTTP round trips and real crypto,
// without requiring an actual Vault server in this sandbox. CI runs the
// same VaultKeyStore code against a real `vault server -dev` for full
// integration confidence.
type fakeTransit struct {
	mount string
	token string

	mu   sync.Mutex
	keys map[string]*fakeKey
}

type fakeKey struct {
	vaultType string
	priv      crypto.Signer
}

func newFakeTransitServer(t *testing.T, mount, token string) *httptest.Server {
	t.Helper()
	ft := &fakeTransit{mount: mount, token: token, keys: make(map[string]*fakeKey)}
	return httptest.NewServer(http.HandlerFunc(ft.handle))
}

func (f *fakeTransit) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Vault-Token") != f.token {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	prefix := "/v1/" + f.mount + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, prefix)

	switch {
	case strings.HasPrefix(rest, "keys/") && r.Method == http.MethodPost:
		f.createKey(w, r, strings.TrimPrefix(rest, "keys/"))
	case strings.HasPrefix(rest, "keys/") && r.Method == http.MethodGet:
		f.readKey(w, strings.TrimPrefix(rest, "keys/"))
	case strings.HasPrefix(rest, "sign/") && r.Method == http.MethodPost:
		f.sign(w, r, strings.TrimPrefix(rest, "sign/"))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeTransit) createKey(w http.ResponseWriter, r *http.Request, name string) {
	var body struct {
		Type string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var signer crypto.Signer
	var err error
	switch body.Type {
	case "ecdsa-p256":
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa-2048":
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	f.mu.Lock()
	f.keys[name] = &fakeKey{vaultType: body.Type, priv: signer}
	f.mu.Unlock()

	writeFakeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{}})
}

func (f *fakeTransit) readKey(w http.ResponseWriter, name string) {
	f.mu.Lock()
	k, ok := f.keys[name]
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	pubDER, err := x509.MarshalPKIXPublicKey(k.priv.Public())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	writeFakeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"type":           k.vaultType,
			"latest_version": 1,
			"keys": map[string]any{
				"1": map[string]any{"public_key": string(pubPEM)},
			},
		},
	})
}

func (f *fakeTransit) sign(w http.ResponseWriter, r *http.Request, name string) {
	f.mu.Lock()
	k, ok := f.keys[name]
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var body struct {
		Input string `json:"input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	digest, err := base64.StdEncoding.DecodeString(body.Input)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var sig []byte
	switch key := k.priv.(type) {
	case *ecdsa.PrivateKey:
		sig, err = ecdsa.SignASN1(rand.Reader, key, digest)
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	writeFakeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(sig),
		},
	})
}

func writeFakeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func newTestVaultKeyStore(t *testing.T) *keystore.VaultKeyStore {
	t.Helper()
	const token = "test-token"
	server := newFakeTransitServer(t, "transit", token)
	t.Cleanup(server.Close)

	ks, err := keystore.NewVaultKeyStore(keystore.VaultConfig{Address: server.URL, TransitMount: "transit"}, token)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// TestFileKeyStoreContract and TestVaultKeyStoreContract both run the
// shared keystore.KeyStore behavioral suite, so the two backends can't
// silently drift in behavior (e.g. Generate's no-overwrite guarantee,
// which keystore.FreshRef's rotation flow depends on).
func TestFileKeyStoreContract(t *testing.T) {
	ks, err := keystore.NewFileKeyStore(t.TempDir(), []byte("test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	keystoretest.Run(t, ks, "storetest-file-key")
}

func TestVaultKeyStoreContract(t *testing.T) {
	keystoretest.Run(t, newTestVaultKeyStore(t), "storetest-vault-key")
}

func TestVaultKeyStoreWrongTokenFails(t *testing.T) {
	server := newFakeTransitServer(t, "transit", "correct-token")
	t.Cleanup(server.Close)

	ks, err := keystore.NewVaultKeyStore(keystore.VaultConfig{Address: server.URL, TransitMount: "transit"}, "wrong-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Exists(t.Context(), "root"); err == nil {
		t.Fatal("Exists with wrong token returned nil error, want error")
	}
}

func TestLoadVaultTokenFromEnv(t *testing.T) {
	os.Unsetenv("TRUSTMATE_VAULT_TOKEN_FILE")
	t.Setenv("TRUSTMATE_VAULT_TOKEN", "env-token")

	token, err := keystore.LoadVaultToken()
	if err != nil {
		t.Fatal(err)
	}
	if token != "env-token" {
		t.Errorf("LoadVaultToken() = %q, want env-token", token)
	}
}

func TestLoadVaultTokenFromFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/token"
	if err := os.WriteFile(path, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRUSTMATE_VAULT_TOKEN_FILE", path)

	token, err := keystore.LoadVaultToken()
	if err != nil {
		t.Fatal(err)
	}
	if token != "file-token" {
		t.Errorf("LoadVaultToken() = %q, want file-token", token)
	}
}

// TestVaultKeyStoreContractAgainstRealVault runs the same contract suite
// against an actual Vault dev server, skipping cleanly when one isn't
// configured -- this sandbox has no Docker available (see AGENTS.md), so
// it can't be exercised locally, but CI's vault service (see
// .github/workflows/ci.yml) sets both env vars, giving real-protocol
// coverage beyond fakeTransit's approximation of the wire format.
func TestVaultKeyStoreContractAgainstRealVault(t *testing.T) {
	addr := os.Getenv("TRUSTMATE_VAULT_TEST_ADDR")
	token := os.Getenv("TRUSTMATE_VAULT_TEST_TOKEN")
	if addr == "" || token == "" {
		t.Skip("TRUSTMATE_VAULT_TEST_ADDR/TRUSTMATE_VAULT_TEST_TOKEN not set; skipping real-Vault-backed test")
	}
	ks, err := keystore.NewVaultKeyStore(keystore.VaultConfig{Address: addr}, token)
	if err != nil {
		t.Fatal(err)
	}
	keystoretest.Run(t, ks, keystore.KeyRef(fmt.Sprintf("ci-vault-key-%d", time.Now().UnixNano())))
}

func TestLoadVaultTokenNeitherSetErrors(t *testing.T) {
	os.Unsetenv("TRUSTMATE_VAULT_TOKEN_FILE")
	os.Unsetenv("TRUSTMATE_VAULT_TOKEN")

	if _, err := keystore.LoadVaultToken(); err == nil {
		t.Fatal("LoadVaultToken with neither env var set returned nil error, want error")
	}
}
