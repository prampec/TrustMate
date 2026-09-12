package api

import (
	"errors"
	"net/http"

	"github.com/prampec/trustmate/internal/store"
)

// roleSatisfies reports whether a caller holding actual may access a
// route that requires min. Admin is a strict superset of Manager, per
// docs/design.md's functional goal that the bootstrap admin cert is
// "added with full access by default".
func roleSatisfies(actual, min store.ClientRole) bool {
	if actual == store.RoleAdmin {
		return true
	}
	return actual == min
}

// requireRole wraps next so it only runs for a caller presenting a
// verified client certificate (chain-checked by crypto/tls itself, since
// the server's tls.Config sets ClientCAs -- see
// internal/bootstrap/server_tls.go) that:
//  1. has a role assigned in the client_roles table, and
//  2. is not itself revoked, and
//  3. holds a role satisfying min.
//
// Every other route stays reachable with no client cert at all: this
// middleware is only applied to the routes docs/design.md's Phase 3
// roadmap calls out as needing auth.
func requireRole(deps Deps, min store.ClientRole, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeError(w, http.StatusUnauthorized, "client certificate required")
			return
		}
		serial := r.TLS.PeerCertificates[0].SerialNumber.String()

		roleRec, err := deps.Store.ClientRoles().Get(r.Context(), serial)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusForbidden, "certificate not authorized")
			return
		}
		if err != nil {
			deps.Logger.Error("looking up client role failed", "serial", serial, "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		certRec, err := deps.Store.Certificates().GetBySerial(r.Context(), serial)
		if err != nil {
			deps.Logger.Error("looking up client certificate failed", "serial", serial, "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if certRec.RevokedAt != nil {
			writeError(w, http.StatusForbidden, "certificate revoked")
			return
		}

		if !roleSatisfies(roleRec.Role, min) {
			writeError(w, http.StatusForbidden, "insufficient role")
			return
		}
		next(w, r)
	}
}
