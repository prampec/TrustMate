package api

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetCAPemRootAndIntermediate(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	for _, path := range []string{"/v1/ca/root.pem", "/v1/ca/intermediate.pem"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want %d", path, rec.Code, http.StatusOK)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/x-pem-file" {
			t.Errorf("%s Content-Type = %q, want application/x-pem-file", path, ct)
		}
		block, _ := pem.Decode(rec.Body.Bytes())
		if block == nil {
			t.Fatalf("%s body is not valid PEM", path)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			t.Errorf("%s body does not parse as a certificate: %v", path, err)
		}
	}
}
