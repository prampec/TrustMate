package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/prampec/trustmate/internal/store"
)

func TestRequireRoleNoCertificate(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	rec := getAs(t, router, "/v1/audit", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireRoleCertificateWithNoRole(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	unassigned := issueClientCert(t, deps, "no-role", "")
	rec := getAs(t, router, "/v1/audit", unassigned)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestRequireRoleManagerCannotAccessAdminRoute(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	manager := issueClientCert(t, deps, "manager", store.RoleManager)
	rec := getAs(t, router, "/v1/audit", manager)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	// A manager can still reach a manager-level route.
	rec = getAs(t, router, "/v1/profiles", manager)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /v1/profiles as manager: status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRequireRoleAdminSatisfiesManagerRoute(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	admin := issueClientCert(t, deps, "admin", store.RoleAdmin)
	rec := getAs(t, router, "/v1/profiles", admin)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /v1/profiles as admin: status = %d, want %d", rec.Code, http.StatusOK)
	}
	rec = getAs(t, router, "/v1/audit", admin)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /v1/audit as admin: status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRequireRoleRevokedCertificateLosesAccess(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	manager := issueClientCert(t, deps, "manager", store.RoleManager)
	rec := getAs(t, router, "/v1/profiles", manager)
	if rec.Code != http.StatusOK {
		t.Fatalf("before revoke: status = %d, want %d", rec.Code, http.StatusOK)
	}

	if err := deps.Store.Certificates().Revoke(context.Background(), manager.SerialNumber.String(), "unspecified", time.Now()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	rec = getAs(t, router, "/v1/profiles", manager)
	if rec.Code != http.StatusForbidden {
		t.Errorf("after revoke: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}
