package api

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/prampec/trustmate/internal/keystore"
	"github.com/prampec/trustmate/internal/store"
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

type rotateTSAResponse struct {
	Serial         string    `json:"serial"`
	PreviousSerial string    `json:"previous_serial"`
	Profile        string    `json:"profile"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	PEM            string    `json:"pem"`
}

// handleRotateTSA mints a new TSA signing identity and hot-swaps the
// running responder to use it for new timestamps. The previous identity
// is left untouched and unrevoked -- timestamps already issued under it
// remain verifiable via whatever TSA cert they embedded, or by fetching
// it by serial through GET /v1/certificates/{serial}. Revoking a
// *compromised* TSA identity remains a separate action via
// POST /v1/certificates/{serial}/revoke; rotation is proactive hygiene,
// not incident response, so it never revokes anything on its own.
//
// Requires admin role: swapping the live signing identity is an
// operational/config change, same reasoning as POST /v1/profiles/reload,
// not a routine certificate operation like POST /v1/certificates.
func handleRotateTSA(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		previous := deps.TSAResponder.CurrentIssuer()

		ref, err := keystore.FreshRef(r.Context(), deps.KeyStore, "tsa")
		if err != nil {
			deps.Logger.Error("allocating TSA keystore ref failed", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		newIssuer, rec, err := tsa.IssueIdentity(r.Context(), ref, tsa.IdentityParams{
			CommonName:        deps.TSACommonName,
			Validity:          deps.TSAValidity,
			PublicBaseURL:     deps.PublicBaseURL,
			RevocationEnabled: deps.ModuleConfig.EnableRevocation,
		}, deps.Store, deps.KeyStore, deps.IntermediateIssuer)
		if err != nil {
			deps.Logger.Error("issuing rotated TSA identity failed", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		deps.TSAResponder.Rotate(newIssuer)

		if err := deps.Store.Audit().Append(r.Context(), store.AuditEntry{
			Timestamp: rec.CreatedAt,
			Actor:     r.RemoteAddr,
			Action:    "tsa-rotate",
			Target:    rec.Serial,
			Detail:    "previous: " + previous.Cert.SerialNumber.String(),
		}); err != nil {
			deps.Logger.Error("writing audit entry failed", "serial", rec.Serial, "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if deps.Metrics != nil {
			deps.Metrics.CertificatesIssuedTotal.WithLabelValues(rec.ProfileName).Inc()
		}

		writeJSON(w, http.StatusOK, rotateTSAResponse{
			Serial:         rec.Serial,
			PreviousSerial: previous.Cert.SerialNumber.String(),
			Profile:        rec.ProfileName,
			NotBefore:      rec.NotBefore,
			NotAfter:       rec.NotAfter,
			PEM:            string(rec.PEM),
		})
	}
}
