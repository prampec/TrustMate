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
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/prampec/trustmate/internal/pki"
	"github.com/prampec/trustmate/internal/profiles"
	"github.com/prampec/trustmate/internal/store"
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

func TestGetCRLRoot(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableRevocation: true})
	router := NewRouter(deps, nil)

	rootRecs, err := deps.Store.Certificates().FindByKind(context.Background(), store.CertKindRoot)
	if err != nil || len(rootRecs) != 1 {
		t.Fatalf("FindByKind(root) = %v, %v; want 1 row", rootRecs, err)
	}
	rootCert := parseCertPEMForTest(t, rootRecs[0].PEM)

	req := httptest.NewRequest(http.MethodGet, "/v1/crl/root.crl", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	crl, err := x509.ParseRevocationList(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if err := crl.CheckSignatureFrom(rootCert); err != nil {
		t.Errorf("root CRL does not verify against root: %v", err)
	}

	// The intermediate cert's own CDP must name this root CRL, not its
	// own (RFC 5280: a CRLDP must point to a CRL signed by the cert's
	// issuer) -- see internal/bootstrap/bootstrap.go's generateIntermediate.
	if len(deps.IntermediateIssuer.Cert.CRLDistributionPoints) != 1 ||
		deps.IntermediateIssuer.Cert.CRLDistributionPoints[0] != deps.PublicBaseURL+"/v1/crl/root.crl" {
		t.Errorf("intermediate CDP = %v, want [%s]", deps.IntermediateIssuer.Cert.CRLDistributionPoints, deps.PublicBaseURL+"/v1/crl/root.crl")
	}
}

func parseCertPEMForTest(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("parseCertPEMForTest: no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parseCertPEMForTest: %v", err)
	}
	return cert
}

// TestPostOCSPForIntermediateCertSignedByRoot verifies an OCSP query
// about the intermediate CA's own certificate is answered by root (its
// actual issuer), not by the intermediate signing for itself -- the OCSP
// analogue of TestGetCRLRoot's CDP check.
func TestPostOCSPForIntermediateCertSignedByRoot(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableRevocation: true})
	router := NewRouter(deps, nil)

	rootRecs, err := deps.Store.Certificates().FindByKind(context.Background(), store.CertKindRoot)
	if err != nil || len(rootRecs) != 1 {
		t.Fatalf("FindByKind(root) = %v, %v; want 1 row", rootRecs, err)
	}
	rootCert := parseCertPEMForTest(t, rootRecs[0].PEM)

	assertOCSPStatus(t, router, rootCert, deps.IntermediateIssuer.Cert, ocsp.Good)
}

func TestPostOCSPGoodAndUnknownAndMalformed(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableRevocation: true})
	router := NewRouter(deps, nil)

	issueRec := postJSON(t, router, "/v1/certificates", issueCertificateRequest{
		Profile: "document-signing",
		CSR:     string(genCSRPEM(t, "known-leaf")),
	}, adminCert(t, deps))
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

func TestRevokeCertificateReflectsInCRLAndOCSP(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableRevocation: true})
	router := NewRouter(deps, nil)
	admin := adminCert(t, deps)

	issueRec := postJSON(t, router, "/v1/certificates", issueCertificateRequest{
		Profile: "document-signing",
		CSR:     string(genCSRPEM(t, "to-be-revoked")),
	}, admin)
	var issued issueCertificateResponse
	if err := json.Unmarshal(issueRec.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(issued.PEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	assertOCSPStatus(t, router, deps.IntermediateIssuer.Cert, leaf, ocsp.Good)

	revokeRec := postJSON(t, router, "/v1/certificates/"+issued.Serial+"/revoke", map[string]string{
		"reason": "keyCompromise",
	}, admin)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want %d; body: %s", revokeRec.Code, http.StatusOK, revokeRec.Body.String())
	}

	// A second revoke of the same serial is a conflict.
	rec := postJSON(t, router, "/v1/certificates/"+issued.Serial+"/revoke", nil, admin)
	if rec.Code != http.StatusConflict {
		t.Errorf("second revoke status = %d, want %d", rec.Code, http.StatusConflict)
	}

	// Revoking an unknown serial is a 404.
	rec = postJSON(t, router, "/v1/certificates/does-not-exist/revoke", nil, admin)
	if rec.Code != http.StatusNotFound {
		t.Errorf("revoke unknown serial status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	assertOCSPStatus(t, router, deps.IntermediateIssuer.Cert, leaf, ocsp.Revoked)

	crlRec := getAs(t, router, "/v1/crl/intermediate.crl", nil)
	if crlRec.Code != http.StatusOK {
		t.Fatalf("GET CRL status = %d, want %d", crlRec.Code, http.StatusOK)
	}
	crl, err := x509.ParseRevocationList(crlRec.Body.Bytes())
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	found := false
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			found = true
		}
	}
	if !found {
		t.Errorf("revoked serial %v not found in CRL entries %v", leaf.SerialNumber, crl.RevokedCertificateEntries)
	}
}

func TestRevokeCertificateRejectsRootAndIntermediate(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)
	admin := adminCert(t, deps)

	for _, kind := range []struct {
		name  string
		field func() (string, error)
	}{
		{"root", func() (string, error) {
			roots, err := deps.Store.Certificates().FindByKind(context.Background(), store.CertKindRoot)
			if err != nil || len(roots) == 0 {
				return "", err
			}
			return roots[0].Serial, nil
		}},
		{"intermediate", func() (string, error) {
			return deps.IntermediateIssuer.Cert.SerialNumber.String(), nil
		}},
	} {
		serial, err := kind.field()
		if err != nil || serial == "" {
			t.Fatalf("%s: resolving serial: %v", kind.name, err)
		}
		rec := postJSON(t, router, "/v1/certificates/"+serial+"/revoke", nil, admin)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("revoking %s (serial %s): status = %d, want %d", kind.name, serial, rec.Code, http.StatusBadRequest)
		}
	}
}

func TestRevokeCertificateRejectsUnknownReason(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableRevocation: true})
	router := NewRouter(deps, nil)
	admin := adminCert(t, deps)

	issueRec := postJSON(t, router, "/v1/certificates", issueCertificateRequest{
		Profile: "document-signing",
		CSR:     string(genCSRPEM(t, "x")),
	}, admin)
	var issued issueCertificateResponse
	if err := json.Unmarshal(issueRec.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}

	rec := postJSON(t, router, "/v1/certificates/"+issued.Serial+"/revoke", map[string]string{
		"reason": "not-a-real-reason",
	}, admin)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
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
