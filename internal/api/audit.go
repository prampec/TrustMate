package api

import (
	"net/http"
	"strconv"
	"time"
)

const (
	defaultAuditLimit = 100
	maxAuditLimit     = 1000
)

type auditEntryResponse struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Detail    string    `json:"detail"`
}

// handleListAudit requires admin role -- the audit trail is a security/
// oversight function, not a day-to-day certificate operation.
func handleListAudit(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := defaultAuditLimit
		if v := r.URL.Query().Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				writeProblem(w, probInvalidParameter, "limit must be a positive integer", map[string]any{"parameter": "limit", "maximum": maxAuditLimit})
				return
			}
			limit = n
		}
		if limit > maxAuditLimit {
			limit = maxAuditLimit
		}

		entries, err := deps.Store.Audit().List(r.Context(), limit)
		if err != nil {
			deps.Logger.Error("listing audit entries failed", "err", err)
			writeInternalError(w)
			return
		}

		out := make([]auditEntryResponse, 0, len(entries))
		for _, e := range entries {
			out = append(out, auditEntryResponse{
				ID:        e.ID,
				Timestamp: e.Timestamp,
				Actor:     e.Actor,
				Action:    e.Action,
				Target:    e.Target,
				Detail:    e.Detail,
			})
		}
		writeJSON(w, http.StatusOK, out)
	}
}
