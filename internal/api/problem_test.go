package api

import (
	"bytes"
	"crypto"
	_ "crypto/sha1"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/digitorus/timestamp"

	"github.com/prampec/trustmate/internal/store"
)

func decodeProblem(t *testing.T, rec *httptest.ResponseRecorder, wantType string) map[string]any {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want application/problem+json (body %s)", ct, rec.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding problem body: %v", err)
	}
	if got := body["type"]; got != problemTypePrefix+wantType {
		t.Errorf("type = %v, want %s", got, problemTypePrefix+wantType)
	}
	if got, ok := body["status"].(float64); !ok || int(got) != rec.Code {
		t.Errorf("status member = %v, want %d", body["status"], rec.Code)
	}
	if title, _ := body["title"].(string); title == "" {
		t.Error("title is empty")
	}
	return body
}

func stringSlice(t *testing.T, v any) []string {
	t.Helper()
	raw, ok := v.([]any)
	if !ok {
		t.Fatalf("%v is not a JSON array", v)
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		out = append(out, e.(string))
	}
	return out
}

func TestProblemUnknownProfileListsAvailableProfiles(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	rec := postJSON(t, router, "/v1/certificates", issueCertificateRequest{
		Profile: "does-not-exist",
		CSR:     string(genCSRPEM(t, "x")),
	}, adminCert(t, deps))

	body := decodeProblem(t, rec, "unknown-profile")
	if got := stringSlice(t, body["available_profiles"]); !slices.Contains(got, "document-signing") {
		t.Errorf("available_profiles = %v, want it to include document-signing", got)
	}
}

func TestProblemMissingFieldsNamesThem(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	rec := postJSON(t, router, "/v1/certificates", issueCertificateRequest{Profile: "document-signing"}, adminCert(t, deps))

	body := decodeProblem(t, rec, "missing-field")
	if got := stringSlice(t, body["missing_fields"]); !slices.Equal(got, []string{"csr"}) {
		t.Errorf("missing_fields = %v, want [csr]", got)
	}
}

func TestProblemMalformedJSON(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	req := withClientCert(httptest.NewRequest(http.MethodPost, "/v1/certificates", bytes.NewReader([]byte("{"))), adminCert(t, deps))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	decodeProblem(t, rec, "malformed-json")
}

func TestProblemInsufficientRoleNamesBothRoles(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	rec := getAs(t, router, "/v1/audit", issueClientCert(t, deps, "manager", store.RoleManager))

	body := decodeProblem(t, rec, "insufficient-role")
	if body["required_role"] != "admin" || body["role"] != "manager" {
		t.Errorf("required_role = %v, role = %v, want admin, manager", body["required_role"], body["role"])
	}
}

func TestProblemNoClientCertificate(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	body := decodeProblem(t, getAs(t, router, "/v1/profiles", nil), "client-certificate-required")
	if body["required_role"] != "manager" {
		t.Errorf("required_role = %v, want manager", body["required_role"])
	}
}

func TestProblemUnknownRevocationReasonListsAllowed(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	rec := postJSON(t, router, "/v1/certificates/1/revoke", revokeCertificateRequest{Reason: "bored"}, adminCert(t, deps))

	body := decodeProblem(t, rec, "unknown-revocation-reason")
	if got := stringSlice(t, body["allowed_values"]); !slices.Contains(got, "keyCompromise") || !slices.IsSorted(got) {
		t.Errorf("allowed_values = %v, want a sorted list including keyCompromise", got)
	}
}

func TestProblemCertificateNotFound(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	rec := getAs(t, router, "/v1/certificates/999999999", adminCert(t, deps))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	decodeProblem(t, rec, "not-found")
}

func TestProblemInvalidRoleListsAllowed(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{})
	router := NewRouter(deps, nil)

	rec := postJSON(t, router, "/v1/clients", issueClientRequest{CSR: string(genCSRPEM(t, "x")), Role: "root"}, adminCert(t, deps))

	body := decodeProblem(t, rec, "invalid-role")
	if got := stringSlice(t, body["allowed_values"]); !slices.Equal(got, []string{"admin", "manager"}) {
		t.Errorf("allowed_values = %v, want [admin manager]", got)
	}
}

func TestProblemTSAUnsupportedContentType(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableTSA: true})
	router := NewRouter(deps, nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/tsa", bytes.NewReader([]byte("x")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	body := decodeProblem(t, rec, "unsupported-media-type")
	if body["expected_content_type"] != "application/timestamp-query" {
		t.Errorf("expected_content_type = %v", body["expected_content_type"])
	}
}

func TestProblemTSARejectsSHA1AsUnsupported(t *testing.T) {
	deps := newTestDeps(t, ModuleConfig{EnableTSA: true})
	router := NewRouter(deps, nil)

	reqDER, err := timestamp.CreateRequest(bytes.NewReader([]byte("hello")), &timestamp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/tsa", bytes.NewReader(reqDER))
	req.Header.Set("Content-Type", "application/timestamp-query")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	decodeProblem(t, rec, "unsupported-timestamp-request")
}
