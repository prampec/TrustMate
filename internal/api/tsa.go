package api

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/prampec/trustmate/internal/tsa"
)

// maxTSARequestBytes bounds how much of a timestamp-query body we read --
// a cheap DoS guard, not the rate limiting docs/design.md's Security
// section still wants on this public, unauthenticated endpoint (deferred
// past Phase 2, same as /v1/ocsp -- see internal/revocation's package
// doc). Matches maxOCSPRequestBytes: RFC 3161 queries are tiny (a hash
// plus an optional nonce/policy OID/extensions), so this is generous
// headroom, not a tight fit.
const maxTSARequestBytes = 64 * 1024

func handleTSA(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if ct := r.Header.Get("Content-Type"); ct != "" && ct != "application/timestamp-query" {
			writeError(w, http.StatusBadRequest, "unsupported content type")
			recordTSAMetrics(deps, "bad_request", start)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxTSARequestBytes+1))
		if err != nil {
			writeError(w, http.StatusBadRequest, "reading request body failed")
			recordTSAMetrics(deps, "bad_request", start)
			return
		}
		if len(body) > maxTSARequestBytes {
			writeError(w, http.StatusBadRequest, "request body too large")
			recordTSAMetrics(deps, "bad_request", start)
			return
		}

		resp, err := deps.TSAResponder.Respond(r.Context(), body)
		if errors.Is(err, tsa.ErrMalformedRequest) || errors.Is(err, tsa.ErrUnsupportedRequest) {
			writeError(w, http.StatusBadRequest, "invalid timestamp request")
			recordTSAMetrics(deps, "bad_request", start)
			return
		}
		if err != nil {
			deps.Logger.Error("TSA responder failed", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			recordTSAMetrics(deps, "error", start)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
		recordTSAMetrics(deps, "ok", start)
	}
}

func recordTSAMetrics(deps Deps, status string, start time.Time) {
	if deps.Metrics == nil {
		return
	}
	deps.Metrics.TSARequestsTotal.WithLabelValues(status).Inc()
	deps.Metrics.TSARequestDuration.Observe(time.Since(start).Seconds())
}
