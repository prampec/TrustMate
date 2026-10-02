package cliclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const problemBody = `{"type":"urn:trustmate:problem:unknown-profile","title":"Unknown certificate profile","status":400,"available_profiles":["server-tls"]}`

func testClient(t *testing.T) *Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ok", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"a":1}`))
	})
	mux.HandleFunc("GET /problem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(problemBody + "\n"))
	})
	mux.HandleFunc("GET /boom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"type":"urn:trustmate:problem:internal-error","title":"Internal error","status":500}`))
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return &Client{http: srv.Client(), baseURL: srv.URL}
}

func TestGetDecodesJSON(t *testing.T) {
	var out map[string]int
	if err := testClient(t).Get("/ok", &out); err != nil {
		t.Fatal(err)
	}
	if out["a"] != 1 {
		t.Errorf("out = %v", out)
	}
}

func TestAPIErrorCarriesProblem(t *testing.T) {
	err := testClient(t).Get("/problem", nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %T %v, want *APIError", err, err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d", apiErr.StatusCode)
	}
	p := apiErr.Problem()
	if p == nil || p["type"] != "urn:trustmate:problem:unknown-profile" {
		t.Errorf("Problem() = %v", p)
	}
	if !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "unknown-profile") {
		t.Errorf("Error() = %q, want status and body", err.Error())
	}
}

func TestProblemNilForNonProblemBody(t *testing.T) {
	e := &APIError{StatusCode: 404, ContentType: "text/plain; charset=utf-8", Body: []byte("404 page not found")}
	if e.Problem() != nil {
		t.Error("Problem() decoded a plain-text body")
	}
}

func TestExitCode(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{&APIError{StatusCode: 400}, ExitRejected},
		{&APIError{StatusCode: 403}, ExitRejected},
		{&APIError{StatusCode: 503}, ExitServer},
		{fmt.Errorf("wrapped: %w", &APIError{StatusCode: 409}), ExitRejected},
		{errors.New("dial tcp: connection refused"), ExitFailure},
	} {
		if got := ExitCode(tc.err); got != tc.want {
			t.Errorf("ExitCode(%v) = %d, want %d", tc.err, got, tc.want)
		}
	}
}

// TestFail re-runs this test binary as a child that calls Fail, since
// Fail exits the process.
func TestFail(t *testing.T) {
	if path := os.Getenv("CLICLIENT_FAIL_PATH"); path != "" {
		Fail("prog", testClient(t).Get(path, nil))
		return
	}
	for _, tc := range []struct {
		path       string
		wantCode   int
		wantStderr string
	}{
		{"/problem", ExitRejected, problemBody},
		{"/boom", ExitServer, `"urn:trustmate:problem:internal-error"`},
	} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFail$")
		cmd.Env = append(os.Environ(), "CLICLIENT_FAIL_PATH="+tc.path)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err := cmd.Run()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != tc.wantCode {
			t.Errorf("%s: exit = %v, want code %d", tc.path, err, tc.wantCode)
		}
		line := strings.TrimSpace(stderr.String())
		if !strings.Contains(line, tc.wantStderr) {
			t.Errorf("%s: stderr = %q, want it to contain %q", tc.path, line, tc.wantStderr)
		}
		if !json.Valid([]byte(line)) {
			t.Errorf("%s: stderr is not a single JSON document: %q", tc.path, line)
		}
	}
}
