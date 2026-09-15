// Package api is the thin REST surface: it validates input, delegates to
// the pki/revocation/tsa/profiles modules, and serializes responses. It
// also owns the cross-cutting HTTP concerns (health checks, metrics,
// request logging) described in docs/design.md.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/prampec/trustmate/internal/store"
	"github.com/prampec/trustmate/internal/version"
)

// ModuleConfig controls which optional route groups are registered.
// The pki core (certificate issuance) is always on; revocation and tsa
// are independently switchable, per docs/design.md's modularity goal.
type ModuleConfig struct {
	EnableRevocation bool
	EnableTSA        bool
	EnableACME       bool
}

// ReadyChecker reports whether the service is ready to take traffic
// (e.g. the datastore is reachable). Returning a non-nil error fails the
// readiness probe.
type ReadyChecker func() error

// NewRouter builds the top-level HTTP handler.
func NewRouter(deps Deps, ready ReadyChecker) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", handleHealthz(deps))
	mux.HandleFunc("GET /readyz", handleReadyz(deps, ready))
	mux.Handle("GET /metrics", handleMetrics(deps))

	// pki core (certificate issuance) is always on. Public PKI artifact
	// distribution (root/intermediate CA certs) needs no auth; everything
	// that reads or mutates the certificate ledger requires at least
	// manager, per docs/design.md's Phase 3 roadmap entry.
	mux.HandleFunc("GET /v1/ca/root.pem", handleCAPem(deps, store.CertKindRoot))
	mux.HandleFunc("GET /v1/ca/intermediate.pem", handleCAPem(deps, store.CertKindIntermediate))
	mux.HandleFunc("POST /v1/certificates", requireRole(deps, store.RoleManager, handleIssueCertificate(deps)))
	mux.HandleFunc("GET /v1/certificates/{serial}", requireRole(deps, store.RoleManager, handleGetCertificate(deps)))
	mux.HandleFunc("POST /v1/certificates/{serial}/revoke", requireRole(deps, store.RoleManager, handleRevokeCertificate(deps)))

	mux.HandleFunc("GET /v1/profiles", requireRole(deps, store.RoleManager, handleListProfiles(deps)))
	mux.HandleFunc("POST /v1/profiles/reload", requireRole(deps, store.RoleAdmin, handleReloadProfiles(deps)))

	mux.HandleFunc("POST /v1/clients", requireRole(deps, store.RoleAdmin, handleIssueClient(deps)))
	mux.HandleFunc("GET /v1/clients", requireRole(deps, store.RoleAdmin, handleListClients(deps)))

	mux.HandleFunc("GET /v1/audit", requireRole(deps, store.RoleAdmin, handleListAudit(deps)))

	if deps.ModuleConfig.EnableRevocation {
		mux.HandleFunc("GET /v1/crl/{ca}", handleCRL(deps))
		mux.HandleFunc("POST /v1/ocsp", handleOCSP(deps))
		deps.Logger.Info("revocation module enabled")
	}
	if deps.ModuleConfig.EnableTSA {
		mux.HandleFunc("POST /v1/tsa", handleTSA(deps))
		mux.HandleFunc("POST /v1/tsa/rotate", requireRole(deps, store.RoleAdmin, handleRotateTSA(deps)))
		deps.Logger.Info("tsa module enabled")
	}

	if deps.ModuleConfig.EnableACME {
		mux.HandleFunc("POST /v1/acme/eab-tokens", requireRole(deps, store.RoleAdmin, handleIssueEABToken(deps)))
		mux.HandleFunc("GET /v1/acme/directory", handleACMEDirectory(deps))
		mux.HandleFunc("GET /v1/acme/new-nonce", handleACMENewNonce(deps))
		mux.HandleFunc("HEAD /v1/acme/new-nonce", handleACMENewNonce(deps))
		mux.HandleFunc("POST /v1/acme/new-account", handleACMENewAccount(deps))
		mux.HandleFunc("POST /v1/acme/new-order", handleACMENewOrder(deps))
		mux.HandleFunc("GET /v1/acme/order/{id}", handleACMEGetOrder(deps))
		mux.HandleFunc("POST /v1/acme/order/{id}/finalize", handleACMEFinalize(deps))
		mux.HandleFunc("GET /v1/acme/authorization/{id}", handleACMEGetAuthorization(deps))
		mux.HandleFunc("GET /v1/acme/certificate/{id}", handleACMECertificate(deps))
		deps.Logger.Info("acme module enabled")
	}

	return withRequestLogging(deps.Logger, mux)
}

func handleHealthz(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "instance": deps.InstanceName, "version": version.Version})
	}
}

func handleReadyz(deps Deps, ready ReadyChecker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ready != nil {
			if err := ready(); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready", "reason": err.Error(), "instance": deps.InstanceName})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready", "instance": deps.InstanceName})
	}
}

// handleMetrics serves Prometheus exposition text from deps.Metrics.
// When deps.Metrics is nil (tests that don't wire metrics up), it falls
// back to the pre-Phase-3 empty-body placeholder rather than panicking.
func handleMetrics(deps Deps) http.Handler {
	if deps.Metrics == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			w.WriteHeader(http.StatusOK)
		})
	}
	return promhttp.HandlerFor(deps.Metrics.Registry, promhttp.HandlerOpts{})
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
