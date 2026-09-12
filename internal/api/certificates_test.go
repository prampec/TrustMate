package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prampec/trustmate/internal/store"
)

func genCSRPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// postJSON issues an authenticated POST (as cert, or anonymously if cert
// is nil) with body JSON-encoded.
func postJSON(t *testing.T, router http.Handler, path string, body any, cert *x509.Certificate) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if cert != nil {
		withClientCert(req, cert)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestIssueCertificateHappyPath(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	rec := postJSON(t, router, "/v1/certificates", issueCertificateRequest{
		Profile: "document-signing",
		CSR:     string(genCSRPEM(t, "doc-signer")),
	}, adminCert(t, deps))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp issueCertificateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.Serial == "" || resp.Profile != "document-signing" {
		t.Errorf("response = %+v, want non-empty serial and profile=document-signing", resp)
	}

	block, _ := pem.Decode([]byte(resp.PEM))
	if block == nil {
		t.Fatal("response PEM does not decode")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing issued certificate: %v", err)
	}
	if leaf.KeyUsage&x509.KeyUsageContentCommitment == 0 {
		t.Errorf("issued leaf KeyUsage = %v, want ContentCommitment set (document-signing profile)", leaf.KeyUsage)
	}

	roots, err := deps.Store.Certificates().FindByKind(context.Background(), store.CertKindRoot)
	if err != nil || len(roots) != 1 {
		t.Fatalf("FindByKind(root) = %v, %v", roots, err)
	}
	rootBlock, _ := pem.Decode(roots[0].PEM)
	rootCert, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	interPool := x509.NewCertPool()
	interPool.AddCert(deps.IntermediateIssuer.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: interPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Errorf("issued leaf does not verify through intermediate to root: %v", err)
	}

	entries, err := deps.Store.Audit().List(context.Background(), 10)
	if err != nil {
		t.Fatalf("Audit().List: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Target == resp.Serial && e.Action == "issue" {
			found = true
		}
	}
	if !found {
		t.Errorf("no audit entry found for issued serial %s", resp.Serial)
	}
}

func TestIssueCertificateUnknownProfile(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	rec := postJSON(t, router, "/v1/certificates", issueCertificateRequest{
		Profile: "does-not-exist",
		CSR:     string(genCSRPEM(t, "x")),
	}, adminCert(t, deps))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestIssueCertificateTamperedCSR(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	csrPEM := genCSRPEM(t, "x")
	block, _ := pem.Decode(csrPEM)
	tampered := append([]byte{}, block.Bytes...)
	tampered[len(tampered)-1] ^= 0xFF
	tamperedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered})

	rec := postJSON(t, router, "/v1/certificates", issueCertificateRequest{
		Profile: "document-signing",
		CSR:     string(tamperedPEM),
	}, adminCert(t, deps))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestIssueCertificateMissingFields(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	rec := postJSON(t, router, "/v1/certificates", issueCertificateRequest{}, adminCert(t, deps))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestIssueCertificateRequiresClientCertificate(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	rec := postJSON(t, router, "/v1/certificates", issueCertificateRequest{
		Profile: "document-signing",
		CSR:     string(genCSRPEM(t, "doc-signer")),
	}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestGetCertificateBySerial(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)
	admin := adminCert(t, deps)

	issueRec := postJSON(t, router, "/v1/certificates", issueCertificateRequest{
		Profile: "document-signing",
		CSR:     string(genCSRPEM(t, "doc-signer")),
	}, admin)
	var issued issueCertificateResponse
	if err := json.Unmarshal(issueRec.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}

	rec := getAs(t, router, "/v1/certificates/"+issued.Serial, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var got certificateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Serial != issued.Serial {
		t.Errorf("Serial = %q, want %q", got.Serial, issued.Serial)
	}

	rec = getAs(t, router, "/v1/certificates/does-not-exist", admin)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown serial status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
