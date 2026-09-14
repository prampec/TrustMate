package keystore

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// VaultKeyStore is a KeyStore backed by HashiCorp Vault's Transit secrets
// engine: key material never leaves Vault, and every Sign call is a
// network round trip to transit/sign/<ref>. This is TrustMate's KMS
// keystore option (docs/design.md's Phase 5 roadmap entry), chosen over
// a single-cloud KMS because Vault is self-hostable and matches
// TrustMate's "no dependency on another product" positioning.
//
// The client is hand-rolled against Vault's plain REST API rather than
// pulling in hashicorp/vault/api -- that SDK drags in ~15 transitive
// dependencies (HCL parsing, retry/backoff, go-sockaddr, ...) for what
// this keystore only ever needs as four small JSON calls, and the
// codebase otherwise has almost no dependencies (see FileKeyStore's own
// hand-rolled AES-GCM/Argon2id, no envelope-encryption library either).
type VaultKeyStore struct {
	addr   string // e.g. "https://vault.internal:8200", no trailing slash
	mount  string // transit secrets engine mount path, e.g. "transit"
	token  string
	client *http.Client

	locks *refLocker
}

// VaultConfig carries the non-secret Vault connection settings loaded
// from config.KeystoreConfig.Vault. The token is supplied separately
// (see LoadVaultToken) so it never ends up alongside a logged
// configuration struct, the same out-of-band handling LoadKEK gives the
// file keystore's passphrase.
type VaultConfig struct {
	Address      string
	TransitMount string
}

// NewVaultKeyStore opens a keystore backed by the Transit engine mounted
// at cfg.TransitMount (default "transit") on the Vault instance at
// cfg.Address, authenticating with token.
func NewVaultKeyStore(cfg VaultConfig, token string) (*VaultKeyStore, error) {
	if cfg.Address == "" {
		return nil, errors.New("keystore: vault address is empty")
	}
	if token == "" {
		return nil, errors.New("keystore: vault token is empty")
	}
	mount := cfg.TransitMount
	if mount == "" {
		mount = "transit"
	}
	return &VaultKeyStore{
		addr:   strings.TrimRight(cfg.Address, "/"),
		mount:  strings.Trim(mount, "/"),
		token:  token,
		client: &http.Client{Timeout: 10 * time.Second},
		locks:  newRefLocker(),
	}, nil
}

// LoadVaultToken resolves the Vault auth token from
// TRUSTMATE_VAULT_TOKEN_FILE or TRUSTMATE_VAULT_TOKEN -- see
// loadSecret.
func LoadVaultToken() (string, error) {
	return loadSecret("TRUSTMATE_VAULT_TOKEN_FILE", "TRUSTMATE_VAULT_TOKEN", "vault auth token")
}

func (v *VaultKeyStore) Exists(ctx context.Context, ref KeyRef) (bool, error) {
	status, _, err := v.do(ctx, http.MethodGet, "keys/"+string(ref), nil)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("keystore: vault key-read %q: unexpected status %d", ref, status)
	}
}

func (v *VaultKeyStore) Generate(ctx context.Context, ref KeyRef, alg Algorithm) (crypto.Signer, error) {
	defer v.locks.lock(ref)()

	exists, err := v.Exists(ctx, ref)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("keystore: key %q already exists", ref)
	}

	vaultType, err := vaultKeyType(alg)
	if err != nil {
		return nil, err
	}
	status, _, err := v.do(ctx, http.MethodPost, "keys/"+string(ref), map[string]string{"type": vaultType})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return nil, fmt.Errorf("keystore: vault key-create %q: unexpected status %d", ref, status)
	}

	return v.Get(ctx, ref)
}

func (v *VaultKeyStore) Get(ctx context.Context, ref KeyRef) (crypto.Signer, error) {
	status, body, err := v.do(ctx, http.MethodGet, "keys/"+string(ref), nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, fmt.Errorf("keystore: key %q not found", ref)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("keystore: vault key-read %q: unexpected status %d", ref, status)
	}

	var resp struct {
		Data struct {
			Type          string `json:"type"`
			LatestVersion int    `json:"latest_version"`
			Keys          map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("keystore: decoding vault key-read response for %q: %w", ref, err)
	}
	versionKey := fmt.Sprintf("%d", resp.Data.LatestVersion)
	versionData, ok := resp.Data.Keys[versionKey]
	if !ok || versionData.PublicKey == "" {
		return nil, fmt.Errorf("keystore: vault key %q has no public key at version %s", ref, versionKey)
	}
	block, _ := pem.Decode([]byte(versionData.PublicKey))
	if block == nil {
		return nil, fmt.Errorf("keystore: key %q: vault returned a non-PEM public key", ref)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keystore: key %q: parsing public key: %w", ref, err)
	}

	sigAlg, hash, err := vaultSignatureParams(resp.Data.Type)
	if err != nil {
		return nil, err
	}
	return &vaultSigner{store: v, ref: ref, public: pub, sigAlg: sigAlg, hash: hash}, nil
}

// do performs one Transit API call and returns the HTTP status code and
// raw response body. A non-2xx/404 network-level error is returned as
// err; the caller interprets status codes (Vault uses 404 for "not
// found", not a JSON error body worth parsing specially).
func (v *VaultKeyStore) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, nil, fmt.Errorf("keystore: encoding vault request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}
	url := fmt.Sprintf("%s/v1/%s/%s", v.addr, v.mount, path)
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return 0, nil, fmt.Errorf("keystore: building vault request: %w", err)
	}
	req.Header.Set("X-Vault-Token", v.token)
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("keystore: vault request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("keystore: reading vault response: %w", err)
	}
	return resp.StatusCode, respBody, nil
}

func vaultKeyType(alg Algorithm) (string, error) {
	switch alg {
	case AlgorithmECDSAP256:
		return "ecdsa-p256", nil
	case AlgorithmRSA2048:
		return "rsa-2048", nil
	default:
		return "", fmt.Errorf("keystore: unsupported algorithm %q", alg)
	}
}

// vaultSignatureParams maps a Transit key type to the signature
// algorithm and hash Sign must request. ECDSA uses Vault's default
// "asn1" marshaling, which returns the same ASN.1 DER (r,s) encoding
// crypto/ecdsa itself produces, so callers see identical signature
// bytes regardless of backend. RSA uses PKCS#1 v1.5, matching what
// crypto/x509.CreateCertificate expects by default from an
// *rsa.PrivateKey-backed crypto.Signer (PSS is opt-in via
// rsa.PSSOptions, which this codebase's leaf/CA templates never set).
func vaultSignatureParams(vaultType string) (sigAlg string, hash crypto.Hash, err error) {
	switch vaultType {
	case "ecdsa-p256":
		return "", crypto.SHA256, nil
	case "rsa-2048":
		return "pkcs1v15", crypto.SHA256, nil
	default:
		return "", 0, fmt.Errorf("keystore: unsupported vault key type %q", vaultType)
	}
}

// vaultSigner implements crypto.Signer against one Transit key. Public()
// is served from the cached key fetched at construction time; Sign()
// calls transit/sign/<ref> for every signature.
type vaultSigner struct {
	store  *VaultKeyStore
	ref    KeyRef
	public crypto.PublicKey
	sigAlg string
	hash   crypto.Hash
}

func (s *vaultSigner) Public() crypto.PublicKey { return s.public }

func (s *vaultSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	reqBody := map[string]any{
		"input":          base64.StdEncoding.EncodeToString(digest),
		"prehashed":      true,
		"hash_algorithm": "sha2-256",
	}
	if s.sigAlg != "" {
		reqBody["signature_algorithm"] = s.sigAlg
	}

	status, body, err := s.store.do(context.Background(), http.MethodPost, "sign/"+string(s.ref), reqBody)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("keystore: vault sign %q: unexpected status %d", s.ref, status)
	}

	var resp struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("keystore: decoding vault sign response for %q: %w", s.ref, err)
	}
	// Vault prefixes signatures with "vault:v<key version>:".
	_, encoded, ok := strings.Cut(resp.Data.Signature, ":")
	if ok {
		_, encoded, ok = strings.Cut(encoded, ":")
	}
	if !ok {
		return nil, fmt.Errorf("keystore: key %q: unrecognized vault signature format %q", s.ref, resp.Data.Signature)
	}
	sig, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("keystore: key %q: decoding vault signature: %w", s.ref, err)
	}
	return sig, nil
}
