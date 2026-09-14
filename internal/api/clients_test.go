package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

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

// failingClientRoleStore wraps a real store.Store, overriding
// ClientRoles() so Assign always fails -- used below to deterministically
// exercise assignRoleOrRevoke's compensating-revoke path (see
// internal/api/certificates.go) without depending on a specific way the
// real ClientRoleRepository can fail.
type failingClientRoleStore struct {
	store.Store
}

func (s failingClientRoleStore) ClientRoles() store.ClientRoleRepository {
	return failingClientRoleRepo{s.Store.ClientRoles()}
}

type failingClientRoleRepo struct {
	store.ClientRoleRepository
}

func (failingClientRoleRepo) Assign(context.Context, store.ClientRoleRecord) error {
	return errors.New("injected role assignment failure")
}

// TestIssueClientCompensatingRevokeAuditsAndDoesNotCountMetric is the
// regression test for two issues a code review caught in
// assignRoleOrRevoke's compensating-revoke path (internal/api/certificates.go):
// it revoked the certificate but never wrote a matching audit entry, so
// the audit log kept claiming a successful issuance for a certificate
// that no longer authorizes anything; and CertificatesIssuedTotal used
// to be incremented before role assignment could fail, overcounting
// certificates that never became usable.
func TestIssueClientCompensatingRevokeAuditsAndDoesNotCountMetric(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	admin := adminCert(t, deps)
	realStore := deps.Store
	deps.Store = failingClientRoleStore{realStore}
	router := NewRouter(deps, nil)

	before := testutil.ToFloat64(deps.Metrics.CertificatesIssuedTotal.WithLabelValues("default"))

	rec := postJSON(t, router, "/v1/clients", issueClientRequest{
		CSR:  string(genCSRPEM(t, "compensating-revoke-client")),
		Role: "manager",
	}, admin)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}

	certs, err := realStore.Certificates().FindByKind(context.Background(), store.CertKindLeaf)
	if err != nil {
		t.Fatal(err)
	}
	var issuedSerial string
	for _, c := range certs {
		if c.Subject == "CN=compensating-revoke-client" {
			issuedSerial = c.Serial
			if c.RevokedAt == nil {
				t.Errorf("certificate %s was not compensating-revoked after the failed role assignment", c.Serial)
			}
		}
	}
	if issuedSerial == "" {
		t.Fatal("no certificate with subject CN=compensating-revoke-client found")
	}

	entries, err := realStore.Audit().List(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	foundRevoke := false
	for _, e := range entries {
		if e.Target == issuedSerial && e.Action == "revoke" {
			foundRevoke = true
		}
	}
	if !foundRevoke {
		t.Errorf("no audit entry recording the compensating revoke of %s; audit log only shows the issuance", issuedSerial)
	}

	after := testutil.ToFloat64(deps.Metrics.CertificatesIssuedTotal.WithLabelValues("default"))
	if after != before {
		t.Errorf("CertificatesIssuedTotal(default) = %v after a compensating-revoked issuance, want unchanged from %v", after, before)
	}
}
