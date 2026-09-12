package api

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/digitorus/timestamp"
)

func TestPostTSAGrantsSignedTokenChainingToIntermediate(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableTSA: true})
	router := NewRouter(deps, nil)

	nonce := big.NewInt(424242)
	reqDER, err := timestamp.CreateRequest(bytes.NewReader([]byte("hello world")), &timestamp.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: true,
		Nonce:        nonce,
	})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/tsa", bytes.NewReader(reqDER))
	req.Header.Set("Content-Type", "application/timestamp-query")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/timestamp-reply" {
		t.Errorf("Content-Type = %q, want application/timestamp-reply", ct)
	}

	ts, err := timestamp.ParseResponse(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if ts.Nonce == nil || ts.Nonce.Cmp(nonce) != 0 {
		t.Errorf("nonce = %v, want %v", ts.Nonce, nonce)
	}

	var tsaCert *x509.Certificate
	for _, c := range ts.Certificates {
		if c.Subject.CommonName == "TrustMate TSA" {
			tsaCert = c
		}
	}
	if tsaCert == nil {
		t.Fatal("TSA certificate not found in response's embedded certificates")
	}
	if err := tsaCert.CheckSignatureFrom(deps.IntermediateIssuer.Cert); err != nil {
		t.Errorf("TSA cert does not chain to intermediate: %v", err)
	}
}

func TestPostTSAMalformedRequest(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableTSA: true})
	router := NewRouter(deps, nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/tsa", bytes.NewReader([]byte("not a timestamp request")))
	req.Header.Set("Content-Type", "application/timestamp-query")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestTSARouteUnregisteredWhenDisabled(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableTSA: false})
	router := NewRouter(deps, nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/tsa", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST /v1/tsa status = %d, want %d (tsa disabled)", rec.Code, http.StatusNotFound)
	}
}
