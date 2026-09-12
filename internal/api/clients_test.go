package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/prampec/trustmate/internal/store"
)

func TestIssueClientAssignsRoleAndGrantsAccess(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)
	admin := adminCert(t, deps)

	rec := postJSON(t, router, "/v1/clients", issueClientRequest{
		CSR:  string(genCSRPEM(t, "new-manager")),
		Role: "manager",
	}, admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var issued issueClientResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	if issued.Role != "manager" {
		t.Errorf("Role = %q, want manager", issued.Role)
	}

	roleRec, err := deps.Store.ClientRoles().Get(context.Background(), issued.Serial)
	if err != nil {
		t.Fatalf("ClientRoles().Get: %v", err)
	}
	if roleRec.Role != store.RoleManager {
		t.Errorf("stored role = %q, want manager", roleRec.Role)
	}

	listRec := getAs(t, router, "/v1/clients", admin)
	if listRec.Code != http.StatusOK {
		t.Fatalf("GET /v1/clients status = %d, want %d", listRec.Code, http.StatusOK)
	}
	var clients []clientResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &clients); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range clients {
		if c.Serial == issued.Serial && c.Role == "manager" {
			found = true
		}
	}
	if !found {
		t.Errorf("issued client %s not found in GET /v1/clients response: %+v", issued.Serial, clients)
	}
}

func TestIssueClientRejectsInvalidRole(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	rec := postJSON(t, router, "/v1/clients", issueClientRequest{
		CSR:  string(genCSRPEM(t, "x")),
		Role: "superuser",
	}, adminCert(t, deps))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestIssueClientRequiresAdminRole(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	manager := issueClientCert(t, deps, "manager", store.RoleManager)
	rec := postJSON(t, router, "/v1/clients", issueClientRequest{
		CSR:  string(genCSRPEM(t, "x")),
		Role: "manager",
	}, manager)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}
