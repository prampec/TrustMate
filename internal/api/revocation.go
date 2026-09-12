package api

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/prampec/trustmate/internal/revocation"
)

// maxOCSPRequestBytes bounds how much of an OCSP request body we read --
// a cheap DoS guard, not the rate limiting docs/design.md's Security
// section still wants on this public, unauthenticated endpoint (deferred
// past Phase 1, see internal/revocation's package doc).
const maxOCSPRequestBytes = 64 * 1024

// handleCRL serves the intermediate CA's CRL. net/http.ServeMux's
// {name} path wildcards must occupy an entire segment, so
// "/v1/crl/{ca}.crl" cannot be registered directly; this handler is
// registered on "/v1/crl/{ca}" and enforces the ".crl" suffix itself.
// Only "intermediate.crl" is served -- one intermediate CA exists in
// Phase 1's scope, no multi-CA hierarchy.
func handleCRL(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ca, ok := strings.CutSuffix(r.PathValue("ca"), ".crl")
		if !ok || ca != "intermediate" {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		der, err := deps.CRLBuilder.CRL(r.Context())
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
		if ct := r.Header.Get("Content-Type"); ct != "" && ct != "application/ocsp-request" {
			writeError(w, http.StatusBadRequest, "unsupported content type")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxOCSPRequestBytes+1))
		if err != nil {
			writeError(w, http.StatusBadRequest, "reading request body failed")
			return
		}
		if len(body) > maxOCSPRequestBytes {
			writeError(w, http.StatusBadRequest, "request body too large")
			return
		}

		resp, err := deps.OCSPResponder.Respond(r.Context(), body)
		if errors.Is(err, revocation.ErrMalformedRequest) {
			writeError(w, http.StatusBadRequest, "invalid OCSP request")
			return
		}
		if err != nil {
			deps.Logger.Error("OCSP responder failed", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
	}
}
