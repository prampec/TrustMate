package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestListAuditAsAdmin(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)
	admin := adminCert(t, deps)

	postJSON(t, router, "/v1/certificates", issueCertificateRequest{
		Profile: "document-signing",
		CSR:     string(genCSRPEM(t, "audited")),
	}, admin)

	rec := getAs(t, router, "/v1/audit", admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var entries []auditEntryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "issue" && e.Detail == "document-signing" {
			found = true
		}
	}
	if !found {
		t.Errorf("no issue audit entry found in %+v", entries)
	}
}

func TestListAuditLimitValidation(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)
	admin := adminCert(t, deps)

	rec := getAs(t, router, "/v1/audit?limit=not-a-number", admin)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
