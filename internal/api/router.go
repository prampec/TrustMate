// Package api is the thin REST surface: it validates input, delegates to
// the pki/revocation/tsa/profiles modules, and serializes responses. It
// also owns the cross-cutting HTTP concerns (health checks, metrics,
// request logging) described in docs/design.md.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
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
func NewRouter(logger *slog.Logger, mods ModuleConfig, ready ReadyChecker) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /readyz", handleReadyz(ready))
	mux.HandleFunc("GET /metrics", handleMetrics)

	// TODO(phase 1): register /v1/ca/*, /v1/certificates* unconditionally
	// (pki core is always on).
	if mods.EnableRevocation {
		// TODO(phase 1): register /v1/crl/{ca}.crl, /v1/ocsp
		logger.Info("revocation module enabled")
	}
	if mods.EnableTSA {
		// TODO(phase 2): register /v1/tsa
		logger.Info("tsa module enabled")
	}

	return withRequestLogging(logger, mux)
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
