// Package api is the thin REST surface: it validates input, delegates to
// the pki/revocation/tsa/profiles modules, and serializes responses. It
// also owns the cross-cutting HTTP concerns (health checks, metrics,
// request logging) described in docs/design.md.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/prampec/trustmate/internal/store"
)

// ModuleConfig controls which optional route groups are registered.
// The pki core (certificate issuance) is always on; revocation and tsa
// are independently switchable, per docs/design.md's modularity goal.
type ModuleConfig struct {
	EnableRevocation bool
	EnableTSA        bool
}

// ReadyChecker reports whether the service is ready to take traffic
// (e.g. the datastore is reachable). Returning a non-nil error fails the
// readiness probe.
type ReadyChecker func() error

// NewRouter builds the top-level HTTP handler.
func NewRouter(deps Deps, ready ReadyChecker) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /readyz", handleReadyz(ready))
	mux.HandleFunc("GET /metrics", handleMetrics)

	// pki core (certificate issuance) is always on.
	mux.HandleFunc("GET /v1/ca/root.pem", handleCAPem(deps, store.CertKindRoot))
	mux.HandleFunc("GET /v1/ca/intermediate.pem", handleCAPem(deps, store.CertKindIntermediate))
	mux.HandleFunc("POST /v1/certificates", handleIssueCertificate(deps))
	mux.HandleFunc("GET /v1/certificates/{serial}", handleGetCertificate(deps))

	if deps.ModuleConfig.EnableRevocation {
		mux.HandleFunc("GET /v1/crl/{ca}", handleCRL(deps))
		mux.HandleFunc("POST /v1/ocsp", handleOCSP(deps))
		deps.Logger.Info("revocation module enabled")
	}
	if deps.ModuleConfig.EnableTSA {
		mux.HandleFunc("POST /v1/tsa", handleTSA(deps))
		deps.Logger.Info("tsa module enabled")
	}

	return withRequestLogging(deps.Logger, mux)
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func handleReadyz(ready ReadyChecker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ready != nil {
			if err := ready(); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "not ready", "reason": err.Error()})
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	}
}

// handleMetrics is a placeholder emitting an empty Prometheus exposition
// body. Real metrics wiring (issuance counts, OCSP/TSA latency, datastore
// health) lands in phase 3 — see docs/design.md.
func handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)
}

func withRequestLogging(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("request", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// writeJSON encodes v as the JSON response body with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a {"error": msg} JSON envelope with the given status.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
