package api

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/prampec/trustmate/internal/revocation"
)

// maxOCSPRequestBytes bounds how much of an OCSP request body we read --
// a cheap DoS guard, not the rate limiting docs/design.md's Security
// section still wants on this public, unauthenticated endpoint (deferred
// past Phase 1, see internal/revocation's package doc).
const maxOCSPRequestBytes = 64 * 1024

// handleCRL serves the root or intermediate CA's CRL. net/http.ServeMux's
// {name} path wildcards must occupy an entire segment, so
// "/v1/crl/{ca}.crl" cannot be registered directly; this handler is
// registered on "/v1/crl/{ca}" and enforces the ".crl" suffix itself.
// Only "root.crl" and "intermediate.crl" are served -- one root and one
// intermediate CA exist in this phase's scope, no multi-CA hierarchy.
func handleCRL(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ca, ok := strings.CutSuffix(r.PathValue("ca"), ".crl")
		if !ok {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		var builder *revocation.CRLBuilder
		switch ca {
		case "intermediate":
			builder = deps.CRLBuilder
		case "root":
			builder = deps.RootCRLBuilder
		default:
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		der, err := builder.CRL(r.Context())
		if err != nil {
			deps.Logger.Error("generating CRL failed", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(der)
	}
}

func handleOCSP(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if ct := r.Header.Get("Content-Type"); ct != "" && ct != "application/ocsp-request" {
			writeError(w, http.StatusBadRequest, "unsupported content type")
			recordOCSPMetrics(deps, "bad_request", start)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxOCSPRequestBytes+1))
		if err != nil {
			writeError(w, http.StatusBadRequest, "reading request body failed")
			recordOCSPMetrics(deps, "bad_request", start)
			return
		}
		if len(body) > maxOCSPRequestBytes {
			writeError(w, http.StatusBadRequest, "request body too large")
			recordOCSPMetrics(deps, "bad_request", start)
			return
		}

		resp, err := deps.OCSPResponder.Respond(r.Context(), body)
		if errors.Is(err, revocation.ErrMalformedRequest) {
			writeError(w, http.StatusBadRequest, "invalid OCSP request")
			recordOCSPMetrics(deps, "bad_request", start)
			return
		}
		if err != nil {
			deps.Logger.Error("OCSP responder failed", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			recordOCSPMetrics(deps, "error", start)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
		recordOCSPMetrics(deps, "ok", start)
	}
}

func recordOCSPMetrics(deps Deps, status string, start time.Time) {
	if deps.Metrics == nil {
		return
	}
	deps.Metrics.OCSPRequestsTotal.WithLabelValues(status).Inc()
	deps.Metrics.OCSPRequestDuration.Observe(time.Since(start).Seconds())
}
