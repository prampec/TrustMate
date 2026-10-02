package api

import (
	"encoding/json"
	"net/http"
)

// problemTypePrefix makes every type URI stable regardless of where the
// service or its docs are hosted; RFC 9457 allows non-dereferenceable
// type URIs. The catalogue is the Problem schema in openapi.yaml, kept in
// sync by TestOpenAPIProblemTypesMatchCatalogue.
const problemTypePrefix = "urn:trustmate:problem:"

// problemType is one entry of the fixed error catalogue. Clients branch on
// the type URI, so a slug must never change meaning once released; add a
// new type instead.
type problemType struct {
	slug   string
	title  string
	status int
}

var (
	probMalformedJSON           = problemType{"malformed-json", "Request body is not valid JSON", http.StatusBadRequest}
	probMissingField            = problemType{"missing-field", "Required field missing", http.StatusBadRequest}
	probInvalidParameter        = problemType{"invalid-parameter", "Invalid query parameter", http.StatusBadRequest}
	probUnknownProfile          = problemType{"unknown-profile", "Unknown certificate profile", http.StatusBadRequest}
	probInvalidCSR              = problemType{"invalid-csr", "Invalid certificate signing request", http.StatusBadRequest}
	probInvalidRole             = problemType{"invalid-role", "Invalid role", http.StatusBadRequest}
	probUnknownRevocationReason = problemType{"unknown-revocation-reason", "Unknown revocation reason", http.StatusBadRequest}
	probNotRevocable            = problemType{"not-revocable", "Certificate cannot be revoked", http.StatusBadRequest}
	probAlreadyRevoked          = problemType{"already-revoked", "Certificate already revoked", http.StatusConflict}
	probNotFound                = problemType{"not-found", "Not found", http.StatusNotFound}
	probProfileReloadFailed     = problemType{"profile-reload-failed", "Profile reload failed", http.StatusBadRequest}
	probProfilesUnavailable     = problemType{"profile-registry-unavailable", "Profile registry not configured", http.StatusServiceUnavailable}
	probUnsupportedMediaType    = problemType{"unsupported-media-type", "Unsupported content type", http.StatusUnsupportedMediaType}
	probBodyUnreadable          = problemType{"body-unreadable", "Request body could not be read", http.StatusBadRequest}
	probBodyTooLarge            = problemType{"body-too-large", "Request body too large", http.StatusBadRequest}
	probInvalidOCSPRequest      = problemType{"invalid-ocsp-request", "Invalid OCSP request", http.StatusBadRequest}
	probInvalidTSARequest       = problemType{"invalid-timestamp-request", "Invalid timestamp request", http.StatusBadRequest}
	probUnsupportedTSARequest   = problemType{"unsupported-timestamp-request", "Unsupported timestamp request", http.StatusBadRequest}
	probClientCertRequired      = problemType{"client-certificate-required", "Client certificate required", http.StatusUnauthorized}
	probClientCertUnauthorized  = problemType{"client-certificate-not-authorized", "Client certificate not authorized", http.StatusForbidden}
	probClientCertRevoked       = problemType{"client-certificate-revoked", "Client certificate revoked", http.StatusForbidden}
	probInsufficientRole        = problemType{"insufficient-role", "Insufficient role", http.StatusForbidden}
	probInternal                = problemType{"internal-error", "Internal error", http.StatusInternalServerError}
)

// writeProblem writes an RFC 9457 application/problem+json body. ext adds
// extension members (e.g. the valid choices for a rejected value) so a
// client, human or agent, can correct the request without guessing; it
// must never carry secrets or internal error text.
func writeProblem(w http.ResponseWriter, p problemType, detail string, ext map[string]any) {
	body := make(map[string]any, len(ext)+4)
	for k, v := range ext {
		body[k] = v
	}
	body["type"] = problemTypePrefix + p.slug
	body["title"] = p.title
	body["status"] = p.status
	if detail != "" {
		body["detail"] = detail
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeInternalError(w http.ResponseWriter) {
	writeProblem(w, probInternal, "", nil)
}
