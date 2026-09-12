package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/prampec/trustmate/internal/store"
)

func TestListProfilesAsManager(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)
	manager := issueClientCert(t, deps, "manager", store.RoleManager)

	rec := getAs(t, router, "/v1/profiles", manager)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var out []profileResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range out {
		if p.Name == "document-signing" {
			found = true
		}
	}
	if !found {
		t.Errorf("document-signing not found in %+v", out)
	}
}

func TestReloadProfilesRequiresAdmin(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)
	manager := issueClientCert(t, deps, "manager", store.RoleManager)

	rec := postJSON(t, router, "/v1/profiles/reload", nil, manager)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	rec = postJSON(t, router, "/v1/profiles/reload", nil, adminCert(t, deps))
	if rec.Code != http.StatusOK {
		t.Errorf("as admin: status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}
