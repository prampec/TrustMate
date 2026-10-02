package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/prampec/trustmate/internal/cliclient"
)

// fakeCA stands in for TrustMate: enough of the REST surface to exercise
// every tool's request shaping and response handling.
type fakeCA struct {
	t          *testing.T
	key        *ecdsa.PrivateKey
	cert       *x509.Certificate
	issueCalls atomic.Int32
	dropNonce  bool
	lastPath   string
}

func newFakeCA(t *testing.T) *fakeCA {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Fake Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &fakeCA{t: t, key: key, cert: cert}
}

func (f *fakeCA) sign(csrPEM string) (string, string) {
	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		f.t.Fatalf("fake CA got bad CSR: %v", err)
	}
	serial := big.NewInt(1000 + int64(f.issueCalls.Add(1)))
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}, f.cert, csr.PublicKey, f.key)
	if err != nil {
		f.t.Fatal(err)
	}
	return serial.String(), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func (f *fakeCA) handler() http.Handler {
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ok", "instance": "Fake"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("GET /v1/ca/intermediate.pem", func(w http.ResponseWriter, r *http.Request) {
		_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: f.cert.Raw})
	})
	mux.HandleFunc("GET /v1/crl/intermediate.crl", func(w http.ResponseWriter, r *http.Request) {
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number:     big.NewInt(7),
			ThisUpdate: time.Now(),
			NextUpdate: time.Now().Add(time.Hour),
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{SerialNumber: big.NewInt(42), RevocationTime: time.Now(), ReasonCode: 1},
			},
		}, f.cert, f.key)
		if err != nil {
			f.t.Fatal(err)
		}
		_, _ = w.Write(der)
	})
	mux.HandleFunc("GET /v1/certificates/{serial}", func(w http.ResponseWriter, r *http.Request) {
		f.lastPath = r.URL.Path
		writeJSON(w, map[string]string{"serial": r.PathValue("serial"), "kind": "leaf"})
	})
	mux.HandleFunc("POST /v1/certificates", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Profile, CSR string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Profile != "tls-server" {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{
				"type": "urn:trustmate:problem:unknown-profile", "title": "Unknown certificate profile", "status": 400,
				"detail": "no profile named " + strconv.Quote(req.Profile), "available_profiles": []string{"tls-server"},
			})
			return
		}
		serial, certPEM := f.sign(req.CSR)
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"serial": serial, "profile": req.Profile, "pem": certPEM})
	})
	mux.HandleFunc("POST /v1/clients", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ CSR, Role string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		serial, certPEM := f.sign(req.CSR)
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"serial": serial, "role": req.Role, "pem": certPEM})
	})
	mux.HandleFunc("POST /v1/certificates/{serial}/revoke", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Reason string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		writeJSON(w, map[string]string{"serial": r.PathValue("serial"), "reason": req.Reason})
	})
	mux.HandleFunc("GET /v1/audit", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, []map[string]string{{"action": "issue", "limit": r.URL.Query().Get("limit")}})
	})
	mux.HandleFunc("POST /v1/tsa", func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/timestamp-query" {
			f.t.Errorf("TSA content type = %q", ct)
		}
		body, _ := io.ReadAll(r.Body)
		req, err := timestamp.ParseRequest(body)
		if err != nil {
			f.t.Fatal(err)
		}
		ts := timestamp.Timestamp{
			HashAlgorithm:     req.HashAlgorithm,
			HashedMessage:     req.HashedMessage,
			Time:              time.Now().UTC().Truncate(time.Second),
			Policy:            asn1.ObjectIdentifier{1, 2, 3, 4},
			AddTSACertificate: true,
		}
		if !f.dropNonce {
			ts.Nonce = req.Nonce
		}
		resp, err := ts.CreateResponseWithOpts(f.cert, f.key, crypto.SHA256)
		if err != nil {
			f.t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(resp)
	})
	return mux
}

type harness struct {
	fake    *fakeCA
	outDir  string
	session *mcp.ClientSession
}

func newHarness(t *testing.T, readOnly bool) *harness {
	t.Helper()
	fake := newFakeCA(t)
	srv := httptest.NewUnstartedServer(fake.handler())
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "server-ca.pem")
	writePEM(t, caPath, "CERTIFICATE", srv.Certificate().Raw)
	certPath, keyPath := writeClientCert(t, dir)

	client, err := cliclient.New(&cliclient.Flags{Server: srv.URL, Cert: certPath, Key: keyPath, CA: caPath})
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	server := newServer(&toolset{client: client, outputDir: outDir}, readOnly)

	ctx := context.Background()
	serverT, clientT := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, serverT, nil); err != nil {
		t.Fatal(err)
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	return &harness{fake: fake, outDir: outDir, session: session}
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeClientCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "mcp-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certPath, keyPath := filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem")
	writePEM(t, certPath, "CERTIFICATE", der)
	writePEM(t, keyPath, "PRIVATE KEY", keyDER)
	return certPath, keyPath
}

// call invokes a tool and decodes its structured output into out (if
// non-nil), returning the tool-level error text when IsError is set.
func (h *harness) call(t *testing.T, name string, args map[string]any, out any) string {
	t.Helper()
	res, err := h.session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", name, err)
	}
	if res.IsError {
		var sb strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				sb.WriteString(tc.Text)
			}
		}
		return sb.String()
	}
	if out != nil {
		data, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatalf("%s: decoding output: %v", name, err)
		}
	}
	return ""
}

func toolNames(t *testing.T, h *harness) []string {
	res, err := h.session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

func TestReadOnlyHidesMutatingTools(t *testing.T) {
	all := toolNames(t, newHarness(t, false))
	ro := toolNames(t, newHarness(t, true))
	for _, name := range []string{"issue_certificate", "revoke_certificate", "issue_client_certificate", "reload_profiles", "rotate_tsa", "timestamp_file"} {
		if !slices.Contains(all, name) {
			t.Errorf("full mode missing %s", name)
		}
		if slices.Contains(ro, name) {
			t.Errorf("read-only mode exposes %s", name)
		}
	}
	if !slices.Contains(ro, "get_certificate") {
		t.Errorf("read-only mode missing get_certificate: %v", ro)
	}
}

func TestIssueCertificateGeneratesKeyLocally(t *testing.T) {
	h := newHarness(t, false)
	var out issuedOutput
	if msg := h.call(t, "issue_certificate", map[string]any{
		"profile": "tls-server", "name": "web01", "common_name": "web01.example.com", "dns_names": []string{"web01.example.com"},
	}, &out); msg != "" {
		t.Fatalf("issue_certificate failed: %s", msg)
	}
	if out.Serial == "" || out.Subject != "CN=web01.example.com" {
		t.Errorf("unexpected output %+v", out)
	}

	info, err := os.Stat(out.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %v, want 0600", info.Mode().Perm())
	}
	if _, err := tls.LoadX509KeyPair(out.CertPath, out.KeyPath); err != nil {
		t.Errorf("written cert and key don't match: %v", err)
	}
}

func TestIssueCertificateRefusesOverwriteBeforeIssuing(t *testing.T) {
	h := newHarness(t, false)
	args := map[string]any{"profile": "tls-server", "name": "dup", "common_name": "dup"}
	if msg := h.call(t, "issue_certificate", args, nil); msg != "" {
		t.Fatal(msg)
	}
	if msg := h.call(t, "issue_certificate", args, nil); !strings.Contains(msg, "already exists") {
		t.Errorf("second issuance error = %q, want 'already exists'", msg)
	}
	if n := h.fake.issueCalls.Load(); n != 1 {
		t.Errorf("server saw %d issuances, want 1", n)
	}
}

func TestIssueCertificateWithCSR(t *testing.T) {
	h := newHarness(t, false)
	_, csrPEM, err := generateKeyAndCSR("", "external", nil)
	if err != nil {
		t.Fatal(err)
	}
	var out issuedOutput
	if msg := h.call(t, "issue_certificate", map[string]any{"profile": "tls-server", "name": "ext", "csr_pem": string(csrPEM)}, &out); msg != "" {
		t.Fatal(msg)
	}
	if out.KeyPath != "" {
		t.Errorf("key_path = %q for a caller-supplied CSR", out.KeyPath)
	}
	if _, err := os.Stat(filepath.Join(h.outDir, "ext.key.pem")); !os.IsNotExist(err) {
		t.Errorf("a key file was written for a caller-supplied CSR")
	}
	if msg := h.call(t, "issue_certificate", map[string]any{"profile": "tls-server", "name": "ext2", "csr_pem": string(csrPEM), "key_type": "rsa-4096"}, nil); msg == "" {
		t.Error("csr_pem combined with key_type was accepted")
	}
}

func TestIssueCertificateServerError(t *testing.T) {
	h := newHarness(t, false)
	msg := h.call(t, "issue_certificate", map[string]any{"profile": "nope", "name": "x", "common_name": "x"}, nil)
	for _, want := range []string{"urn:trustmate:problem:unknown-profile", `"available_profiles":["tls-server"]`} {
		if !strings.Contains(msg, want) {
			t.Errorf("error = %q, want server's problem document passed through (missing %s)", msg, want)
		}
	}
	if entries, _ := os.ReadDir(h.outDir); len(entries) != 0 {
		t.Errorf("files written despite server error: %v", entries)
	}
}

func TestInputValidation(t *testing.T) {
	h := newHarness(t, false)
	cases := []struct {
		tool string
		args map[string]any
	}{
		{"issue_certificate", map[string]any{"profile": "tls-server", "name": "../escape", "common_name": "x"}},
		{"issue_certificate", map[string]any{"profile": "tls-server", "name": "/abs", "common_name": "x"}},
		{"issue_certificate", map[string]any{"profile": "tls-server", "name": "weak", "common_name": "x", "key_type": "rsa-2048"}},
		{"issue_client_certificate", map[string]any{"role": "root", "name": "c", "common_name": "c"}},
		{"get_certificate", map[string]any{"serial": "1/../../clients"}},
		{"revoke_certificate", map[string]any{"serial": "abc"}},
		{"get_crl", map[string]any{"ca": "../ca/root.pem"}},
	}
	for _, c := range cases {
		if msg := h.call(t, c.tool, c.args, nil); msg == "" {
			t.Errorf("%s %v: accepted, want error", c.tool, c.args)
		}
	}
	if n := h.fake.issueCalls.Load(); n != 0 {
		t.Errorf("server saw %d issuances for invalid input", n)
	}
	if h.fake.lastPath != "" {
		t.Errorf("invalid serial reached the server as %q", h.fake.lastPath)
	}
}

func TestIssueClientCertificate(t *testing.T) {
	h := newHarness(t, false)
	var out issuedOutput
	if msg := h.call(t, "issue_client_certificate", map[string]any{"role": "manager", "name": "ci-bot", "common_name": "ci-bot"}, &out); msg != "" {
		t.Fatal(msg)
	}
	if out.Role != "manager" || out.KeyPath == "" || out.CertPath == "" {
		t.Errorf("unexpected output %+v", out)
	}
}

func TestReadTools(t *testing.T) {
	h := newHarness(t, true)

	var health healthOutput
	if msg := h.call(t, "get_health", nil, &health); msg != "" || health.Readiness["status"] != "ready" {
		t.Errorf("get_health = %+v, %q", health, msg)
	}

	var ca caCertificateOutput
	if msg := h.call(t, "get_ca_certificate", map[string]any{"ca": "intermediate"}, &ca); msg != "" || ca.Subject != "CN=Fake Intermediate CA" {
		t.Errorf("get_ca_certificate = %+v, %q", ca, msg)
	}

	var crl crlOutput
	if msg := h.call(t, "get_crl", map[string]any{"ca": "intermediate"}, &crl); msg != "" {
		t.Fatal(msg)
	}
	if crl.Number != "7" || len(crl.Revoked) != 1 || crl.Revoked[0].Serial != "42" || crl.Revoked[0].Reason != 1 {
		t.Errorf("get_crl = %+v", crl)
	}

	var audit auditOutput
	if msg := h.call(t, "list_audit", map[string]any{"limit": 5}, &audit); msg != "" || len(audit.Entries) != 1 || audit.Entries[0]["limit"] != "5" {
		t.Errorf("list_audit = %+v, %q", audit, msg)
	}

	var cert map[string]any
	if msg := h.call(t, "get_certificate", map[string]any{"serial": "12345"}, &cert); msg != "" || cert["serial"] != "12345" {
		t.Errorf("get_certificate = %+v, %q", cert, msg)
	}
}

func TestRevokeCertificate(t *testing.T) {
	h := newHarness(t, false)
	var out map[string]any
	if msg := h.call(t, "revoke_certificate", map[string]any{"serial": "1001", "reason": "keyCompromise"}, &out); msg != "" {
		t.Fatal(msg)
	}
	if out["serial"] != "1001" || out["reason"] != "keyCompromise" {
		t.Errorf("revoke_certificate = %+v", out)
	}
}

func TestTimestampFile(t *testing.T) {
	h := newHarness(t, false)
	doc := filepath.Join(t.TempDir(), "contract.txt")
	if err := os.WriteFile(doc, []byte("signed and sealed"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out timestampOutput
	if msg := h.call(t, "timestamp_file", map[string]any{"file": doc, "name": "contract"}, &out); msg != "" {
		t.Fatal(msg)
	}
	sum := sha256.Sum256([]byte("signed and sealed"))
	if out.Policy != "1.2.3.4" || out.SHA256 != hex.EncodeToString(sum[:]) || out.TSA != "CN=Fake Intermediate CA" {
		t.Errorf("unexpected output %+v", out)
	}
	reply, err := os.ReadFile(out.TokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := timestamp.ParseResponse(reply); err != nil {
		t.Errorf("saved token doesn't parse: %v", err)
	}

	h.fake.dropNonce = true
	if msg := h.call(t, "timestamp_file", map[string]any{"file": doc, "name": "replay"}, nil); !strings.Contains(msg, "nonce") {
		t.Errorf("reply without nonce: error = %q", msg)
	}
	if _, err := os.Stat(filepath.Join(h.outDir, "replay.tsr")); !os.IsNotExist(err) {
		t.Error("mismatched token was written")
	}
}
