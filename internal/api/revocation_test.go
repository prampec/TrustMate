package api

import (
	"bytes"
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
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/prampec/trustmate/internal/pki"
	"github.com/prampec/trustmate/internal/profiles"
)

func TestGetCRLIntermediate(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableRevocation: true})
	router := NewRouter(deps, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/crl/intermediate.crl", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/pkix-crl" {
		t.Errorf("Content-Type = %q, want application/pkix-crl", ct)
	}
	crl, err := x509.ParseRevocationList(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if err := crl.CheckSignatureFrom(deps.IntermediateIssuer.Cert); err != nil {
		t.Errorf("CRL does not verify against intermediate: %v", err)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/crl/bogus.crl", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("bogus.crl status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestPostOCSPGoodAndUnknownAndMalformed(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableRevocation: true})
	router := NewRouter(deps, nil)

	issueRec := postJSON(t, router, "/v1/certificates", issueCertificateRequest{
		Profile: "document-signing",
		CSR:     string(genCSRPEM(t, "known-leaf")),
	})
	var issued issueCertificateResponse
	if err := json.Unmarshal(issueRec.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(issued.PEM))
	knownCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	unknownCert := issueLeafNotPersisted(t, deps.IntermediateIssuer)

	assertOCSPStatus(t, router, deps.IntermediateIssuer.Cert, knownCert, ocsp.Good)
	assertOCSPStatus(t, router, deps.IntermediateIssuer.Cert, unknownCert, ocsp.Unknown)

	req := httptest.NewRequest(http.MethodPost, "/v1/ocsp", bytes.NewReader([]byte("not an ocsp request")))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("garbage OCSP request status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestRevocationRoutesUnregisteredWhenDisabled(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableRevocation: false})
	router := NewRouter(deps, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/crl/intermediate.crl", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /v1/crl/intermediate.crl status = %d, want %d (revocation disabled)", rec.Code, http.StatusNotFound)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/ocsp", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST /v1/ocsp status = %d, want %d (revocation disabled)", rec.Code, http.StatusNotFound)
	}
}

func issueLeafNotPersisted(t *testing.T, issuer pki.Issuer) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert, err := pki.IssueLeaf(profiles.DocumentSigning(), pkix.Name{CommonName: "unknown-leaf"}, key.Public(),
		issuer, now, now.Add(time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func assertOCSPStatus(t *testing.T, router http.Handler, issuerCert, leafCert *x509.Certificate, wantStatus int) {
	t.Helper()
	reqDER, err := ocsp.CreateRequest(leafCert, issuerCert, nil)
	if err != nil {
		t.Fatalf("ocsp.CreateRequest: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/ocsp", bytes.NewReader(reqDER))
	req.Header.Set("Content-Type", "application/ocsp-request")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	resp, err := ocsp.ParseResponse(rec.Body.Bytes(), issuerCert)
	if err != nil {
		t.Fatalf("ocsp.ParseResponse: %v", err)
	}
	if resp.Status != wantStatus {
		t.Errorf("status = %d, want %d", resp.Status, wantStatus)
	}
}
