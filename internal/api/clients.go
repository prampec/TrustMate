package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/prampec/trustmate/internal/pki"
	"github.com/prampec/trustmate/internal/profiles"
	"github.com/prampec/trustmate/internal/store"
)

type issueClientRequest struct {
	CSR  string `json:"csr"`
	Role string `json:"role"`
}

type issueClientResponse struct {
	Serial string `json:"serial"`
	Role   string `json:"role"`
	PEM    string `json:"pem"`
}

// handleIssueClient issues a new API client access certificate (against
// the built-in client-auth profile -- see profiles.Default) and assigns
// it a role in client_roles. Requires admin role: onboarding a new API
// caller is a configuration change, not a certificate operation. There
// is deliberately no separate "deactivate client" route -- POST
// /v1/certificates/{serial}/revoke on a client cert's serial cuts off
// its API access too, since requireRole checks revoked_at.
func handleIssueClient(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req issueClientRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "malformed JSON body")
			return
		}
		if req.CSR == "" {
			writeError(w, http.StatusBadRequest, "csr is required")
			return
		}
		role := store.ClientRole(req.Role)
		if role != store.RoleAdmin && role != store.RoleManager {
			writeError(w, http.StatusBadRequest, "role must be \"admin\" or \"manager\"")
			return
		}

		csr, err := pki.ParseCSR([]byte(req.CSR))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid CSR: "+err.Error())
			return
		}

		profile := profiles.Default().WithIssuerURLs(deps.PublicBaseURL, deps.ModuleConfig.EnableRevocation)
		now := time.Now()
		cert, err := pki.IssueLeaf(profile, csr.Subject, csr.PublicKey,
			deps.IntermediateIssuer, now, now.Add(profile.Validity), nil)
		if err != nil {
			deps.Logger.Error("issuing client certificate failed", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		rec := store.CertificateRecord{
			Serial:       cert.SerialNumber.String(),
			Kind:         store.CertKindLeaf,
			ProfileName:  profile.Name,
			Subject:      cert.Subject.String(),
			IssuerSerial: deps.IntermediateIssuer.Cert.SerialNumber.String(),
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			PEM:          encodeCertPEM(cert.Raw),
			CreatedAt:    now.UTC(),
		}
		if err := deps.Store.Certificates().Create(r.Context(), rec); err != nil {
			deps.Logger.Error("persisting client certificate failed", "serial", rec.Serial, "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if err := deps.Store.ClientRoles().Assign(r.Context(), store.ClientRoleRecord{
			CertSerial: rec.Serial,
			Role:       role,
			CreatedAt:  now.UTC(),
		}); err != nil {
			deps.Logger.Error("assigning client role failed", "serial", rec.Serial, "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if err := deps.Store.Audit().Append(r.Context(), store.AuditEntry{
			Timestamp: now.UTC(),
			Actor:     r.RemoteAddr,
			Action:    "client-issue",
			Target:    rec.Serial,
			Detail:    string(role),
		}); err != nil {
			deps.Logger.Error("writing audit entry failed", "serial", rec.Serial, "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if deps.Metrics != nil {
			deps.Metrics.CertificatesIssuedTotal.WithLabelValues(profile.Name).Inc()
		}

		writeJSON(w, http.StatusCreated, issueClientResponse{
			Serial: rec.Serial,
			Role:   string(role),
			PEM:    string(rec.PEM),
		})
	}
}

type clientResponse struct {
	Serial    string     `json:"serial"`
	Role      string     `json:"role"`
	Subject   string     `json:"subject"`
	NotAfter  time.Time  `json:"not_after"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// handleListClients requires admin role.
func handleListClients(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		roles, err := deps.Store.ClientRoles().List(r.Context())
		if err != nil {
			deps.Logger.Error("listing client roles failed", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		out := make([]clientResponse, 0, len(roles))
		for _, roleRec := range roles {
			certRec, err := deps.Store.Certificates().GetBySerial(r.Context(), roleRec.CertSerial)
			if err != nil {
				deps.Logger.Error("looking up client certificate failed", "serial", roleRec.CertSerial, "err", err)
				writeError(w, http.StatusInternalServerError, "internal error")
				return
			}
			out = append(out, clientResponse{
				Serial:    certRec.Serial,
				Role:      string(roleRec.Role),
				Subject:   certRec.Subject,
				NotAfter:  certRec.NotAfter,
				RevokedAt: certRec.RevokedAt,
			})
		}
		writeJSON(w, http.StatusOK, out)
	}
}
