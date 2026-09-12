package api

import (
	"bytes"
	"crypto"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/digitorus/timestamp"

	"github.com/prampec/trustmate/internal/store"
)

func TestRotateTSARequiresAdmin(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableTSA: true})
	router := NewRouter(deps, nil)

	manager := issueClientCert(t, deps, "manager", store.RoleManager)
	rec := postJSON(t, router, "/v1/tsa/rotate", nil, manager)
	if rec.Code != http.StatusForbidden {
		t.Errorf("as manager: status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	rec = postJSON(t, router, "/v1/tsa/rotate", nil, adminCert(t, deps))
	if rec.Code != http.StatusOK {
		t.Fatalf("as admin: status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestRotateTSASwapsSigningIdentityAndKeepsOldCertFetchable(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableTSA: true})
	router := NewRouter(deps, nil)
	admin := adminCert(t, deps)

	before := deps.TSAResponder.CurrentIssuer()

	rec := postJSON(t, router, "/v1/tsa/rotate", nil, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp rotateTSAResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Serial == "" || resp.Serial == resp.PreviousSerial {
		t.Errorf("response = %+v, want a new non-empty serial distinct from previous_serial", resp)
	}
	if resp.PreviousSerial != before.Cert.SerialNumber.String() {
		t.Errorf("PreviousSerial = %q, want %q", resp.PreviousSerial, before.Cert.SerialNumber.String())
	}
	if resp.Profile != "tsa" {
		t.Errorf("Profile = %q, want tsa", resp.Profile)
	}

	// A subsequent /v1/tsa request (certReq=true) now embeds the NEW cert.
	nonce := big.NewInt(42)
	reqDER, err := timestamp.CreateRequest(bytes.NewReader([]byte("hello")), &timestamp.RequestOptions{
		Hash: crypto.SHA256, Certificates: true, Nonce: nonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	tsaReq := httptest.NewRequest(http.MethodPost, "/v1/tsa", bytes.NewReader(reqDER))
	tsaReq.Header.Set("Content-Type", "application/timestamp-query")
	tsaRec := httptest.NewRecorder()
	router.ServeHTTP(tsaRec, tsaReq)
	if tsaRec.Code != http.StatusOK {
		t.Fatalf("POST /v1/tsa status = %d, want %d", tsaRec.Code, http.StatusOK)
	}
	ts, err := timestamp.ParseResponse(tsaRec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(ts.Certificates) == 0 || ts.Certificates[0].SerialNumber.String() != resp.Serial {
		t.Errorf("post-rotation /v1/tsa embedded cert serial = %v, want %s", ts.Certificates, resp.Serial)
	}

	// The pre-rotation TSA cert is still fetchable by serial.
	getRec := getAs(t, router, "/v1/certificates/"+resp.PreviousSerial, admin)
	if getRec.Code != http.StatusOK {
		t.Errorf("GET pre-rotation TSA cert status = %d, want %d", getRec.Code, http.StatusOK)
	}

	// An audit entry for the rotation exists.
	auditRec := getAs(t, router, "/v1/audit", admin)
	if auditRec.Code != http.StatusOK {
		t.Fatalf("GET /v1/audit status = %d, want %d", auditRec.Code, http.StatusOK)
	}
	var entries []auditEntryResponse
	if err := json.Unmarshal(auditRec.Body.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "tsa-rotate" && e.Target == resp.Serial {
			found = true
		}
	}
	if !found {
		t.Errorf("no tsa-rotate audit entry found for serial %s in %+v", resp.Serial, entries)
	}
}

func TestRotateTSARouteUnregisteredWhenTSADisabled(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableTSA: false})
	router := NewRouter(deps, nil)

	rec := postJSON(t, router, "/v1/tsa/rotate", nil, adminCert(t, deps))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d (tsa disabled)", rec.Code, http.StatusNotFound)
	}
}
