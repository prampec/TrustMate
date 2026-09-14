package api

import (
	"context"
	"crypto"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/prampec/trustmate/internal/pki"
	"github.com/prampec/trustmate/internal/profiles"
	"github.com/prampec/trustmate/internal/store"
)

func encodeCertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// lookupProfile resolves name against deps.Profiles when set, falling
// back to the compiled-in built-ins otherwise -- so Deps values built
// without a Registry (older tests, primarily) keep working unchanged.
func lookupProfile(deps Deps, name string) (profiles.Profile, bool) {
	if deps.Profiles != nil {
		return deps.Profiles.Lookup(name)
	}
	return profiles.Lookup(name)
}

// revocationReasons is the fixed set of RFC 5280 reason strings this API
// accepts on POST /v1/certificates/{serial}/revoke -- kept small and
// hardcoded rather than exposing the full CRLReason enum (e.g.
// certificateHold/removeFromCRL don't make sense without a hold/unhold
// workflow this phase doesn't build).
var revocationReasons = map[string]bool{
	"unspecified":          true,
	"keyCompromise":        true,
	"affiliationChanged":   true,
	"superseded":           true,
	"cessationOfOperation": true,
}

// issueLeafCertificate builds and signs a leaf certificate from profile
// against subject/publicKey/dnsNames, persists it, and appends an audit
// entry -- the sequence every leaf-issuing route needs
// (POST /v1/certificates, POST /v1/clients, and the ACME finalize
// handler in internal/api/acme.go), factored out so it's defined once
// rather than three times. It deliberately does NOT increment
// CertificatesIssuedTotal: POST /v1/clients and ACME finalize both still
// have a role-assignment step that can compensating-revoke this
// certificate before it's ever usable (see assignRoleOrRevoke), so each
// caller increments the metric itself once it knows the certificate is
// actually staying issued.
func issueLeafCertificate(ctx context.Context, deps Deps, profile profiles.Profile, subject pkix.Name, publicKey crypto.PublicKey, dnsNames []string, now time.Time, actor, auditAction, auditDetail string) (store.CertificateRecord, error) {
	cert, err := pki.IssueLeaf(profile, subject, publicKey, deps.IntermediateIssuer, now, now.Add(profile.Validity), dnsNames)
	if err != nil {
		return store.CertificateRecord{}, fmt.Errorf("issuing certificate: %w", err)
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
	if err := deps.Store.Certificates().Create(ctx, rec); err != nil {
		return store.CertificateRecord{}, fmt.Errorf("persisting issued certificate: %w", err)
	}
	if err := deps.Store.Audit().Append(ctx, store.AuditEntry{
		Timestamp: now.UTC(),
		Actor:     actor,
		Action:    auditAction,
		Target:    rec.Serial,
		Detail:    auditDetail,
	}); err != nil {
		return store.CertificateRecord{}, fmt.Errorf("writing audit entry: %w", err)
	}
	return rec, nil
}

// assignRoleOrRevoke assigns role to rec.Serial. issueLeafCertificate
// has already persisted the certificate and written an audit entry by
// the time callers reach this, so on assignment failure it attempts a
// compensating revoke of that certificate rather than leaving a
// certificate that authenticates via mTLS but authorizes nothing --
// every requireRole check would silently deny it, while the audit log
// still claims a successful issuance. Returns the original assignment
// error either way (the compensating revoke's own failure is only
// logged, since there's no more informative error to surface to the
// caller than the one that triggered it).
func assignRoleOrRevoke(ctx context.Context, deps Deps, rec store.CertificateRecord, role store.ClientRole, now time.Time) error {
	err := deps.Store.ClientRoles().Assign(ctx, store.ClientRoleRecord{
		CertSerial: rec.Serial,
		Role:       role,
		CreatedAt:  now.UTC(),
	})
	if err == nil {
		return nil
	}
	if revokeErr := deps.Store.Certificates().Revoke(ctx, rec.Serial, "unspecified", now); revokeErr != nil {
		deps.Logger.Error("compensating revoke after failed role assignment also failed", "serial", rec.Serial, "err", revokeErr)
		return err
	}
	// Every other revocation path (handleRevokeCertificate) appends a
	// matching audit entry; without one here the audit log would keep
	// showing only the original issuance for a certificate that no
	// longer works, misrepresenting its real state.
	if auditErr := deps.Store.Audit().Append(ctx, store.AuditEntry{
		Timestamp: now.UTC(),
		Actor:     "system:compensating-revoke",
		Action:    "revoke",
		Target:    rec.Serial,
		Detail:    "unspecified",
	}); auditErr != nil {
		deps.Logger.Error("writing compensating-revoke audit entry failed", "serial", rec.Serial, "err", auditErr)
	}
	return err
}

type issueCertificateRequest struct {
	Profile string `json:"profile"`
	CSR     string `json:"csr"`
}

type issueCertificateResponse struct {
	Serial    string    `json:"serial"`
	Profile   string    `json:"profile"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	PEM       string    `json:"pem"`
}

// handleIssueCertificate issues a leaf certificate from a submitted CSR
// against a named profile. The CSR's Subject/SANs are honored as
// submitted (after verifying its self-signature proves possession of the
// private key); KeyUsage/ExtKeyUsage/validity/AIA/CDP/OCSP all come from
// the named profile, never the CSR -- a requester picks *what kind* of
// certificate they want by naming a profile, not by smuggling policy
// fields into the CSR.
//
// Requires manager (or admin) role -- see internal/api/auth.go and
// docs/design.md's Phase 3 roadmap entry.
func handleIssueCertificate(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req issueCertificateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "malformed JSON body")
			return
		}
		if req.Profile == "" || req.CSR == "" {
			writeError(w, http.StatusBadRequest, "profile and csr are required")
			return
		}

		profile, ok := lookupProfile(deps, req.Profile)
		if !ok {
			writeError(w, http.StatusBadRequest, "unknown profile")
			return
		}

		csr, err := pki.ParseCSR([]byte(req.CSR))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid CSR: "+err.Error())
			return
		}

		profile = profile.WithIssuerURLs(deps.PublicBaseURL, deps.ModuleConfig.EnableRevocation)
		now := time.Now()
		rec, err := issueLeafCertificate(r.Context(), deps, profile, csr.Subject, csr.PublicKey, csr.DNSNames, now, r.RemoteAddr, "issue", profile.Name)
		if err != nil {
			deps.Logger.Error("issuing certificate failed", "profile", profile.Name, "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		// No role-assignment step on this route (unlike POST /v1/clients
		// and ACME finalize), so the certificate is usable the instant
		// it's issued -- safe to count immediately.
		if deps.Metrics != nil {
			deps.Metrics.CertificatesIssuedTotal.WithLabelValues(profile.Name).Inc()
		}
		writeJSON(w, http.StatusCreated, issueCertificateResponse{
			Serial:    rec.Serial,
			Profile:   profile.Name,
			NotBefore: rec.NotBefore,
			NotAfter:  rec.NotAfter,
			PEM:       string(rec.PEM),
		})
	}
}

type certificateResponse struct {
	Serial           string     `json:"serial"`
	Kind             string     `json:"kind"`
	Profile          string     `json:"profile"`
	Subject          string     `json:"subject"`
	IssuerSerial     string     `json:"issuer_serial"`
	NotBefore        time.Time  `json:"not_before"`
	NotAfter         time.Time  `json:"not_after"`
	PEM              string     `json:"pem"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason string     `json:"revocation_reason,omitempty"`
}

func handleGetCertificate(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec, err := deps.Store.Certificates().GetBySerial(r.Context(), r.PathValue("serial"))
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if err != nil {
			deps.Logger.Error("looking up certificate failed", "serial", r.PathValue("serial"), "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusOK, certificateResponse{
			Serial:           rec.Serial,
			Kind:             string(rec.Kind),
			Profile:          rec.ProfileName,
			Subject:          rec.Subject,
			IssuerSerial:     rec.IssuerSerial,
			NotBefore:        rec.NotBefore,
			NotAfter:         rec.NotAfter,
			PEM:              string(rec.PEM),
			RevokedAt:        rec.RevokedAt,
			RevocationReason: rec.RevocationReason,
		})
	}
}

type revokeCertificateRequest struct {
	Reason string `json:"reason"`
}

type revokeCertificateResponse struct {
	Serial    string    `json:"serial"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason    string    `json:"reason"`
}

// handleRevokeCertificate marks a certificate revoked, immediately
// invalidating the cached CRL so the next fetch reflects it (rather than
// waiting out CRLBuilder's 24h cache) and making it show up as "revoked"
// on the next OCSP query. Requires manager (or admin) role, same as
// issuance -- see internal/api/auth.go.
func handleRevokeCertificate(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		serial := r.PathValue("serial")

		var req revokeCertificateRequest
		if r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeError(w, http.StatusBadRequest, "malformed JSON body")
				return
			}
		}
		if req.Reason == "" {
			req.Reason = "unspecified"
		}
		if !revocationReasons[req.Reason] {
			writeError(w, http.StatusBadRequest, "unknown reason")
			return
		}

		rec, err := deps.Store.Certificates().GetBySerial(r.Context(), serial)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if err != nil {
			deps.Logger.Error("looking up certificate failed", "serial", serial, "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		// Root/intermediate CA certificates aren't revocable through this
		// route -- they're structural anchors, not day-to-day certificate
		// operations, and nothing in the CRL/OCSP/issuance path checks
		// whether the issuing CA itself is "revoked".
		if rec.Kind != store.CertKindLeaf {
			writeError(w, http.StatusBadRequest, "only leaf certificates can be revoked")
			return
		}

		now := time.Now()
		err = deps.Store.Certificates().Revoke(r.Context(), serial, req.Reason, now)
		if errors.Is(err, store.ErrAlreadyRevoked) {
			writeError(w, http.StatusConflict, "already revoked")
			return
		}
		if err != nil {
			deps.Logger.Error("revoking certificate failed", "serial", serial, "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		if err := deps.Store.Audit().Append(r.Context(), store.AuditEntry{
			Timestamp: now.UTC(),
			Actor:     r.RemoteAddr,
			Action:    "revoke",
			Target:    serial,
			Detail:    req.Reason,
		}); err != nil {
			deps.Logger.Error("writing audit entry failed", "serial", serial, "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if deps.CRLBuilder != nil {
			deps.CRLBuilder.Invalidate()
		}
		if deps.Metrics != nil {
			deps.Metrics.CertificatesRevokedTotal.Inc()
		}

		writeJSON(w, http.StatusOK, revokeCertificateResponse{
			Serial:    serial,
			RevokedAt: now.UTC(),
			Reason:    req.Reason,
		})
	}
}
