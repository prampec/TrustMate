package api

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"time"

	"github.com/prampec/trustmate/internal/pki"
	"github.com/prampec/trustmate/internal/profiles"
	"github.com/prampec/trustmate/internal/store"
)

func encodeCertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
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
// This route is unauthenticated in Phase 1 -- see docs/design.md's
// Phase 3 roadmap entry for request-level auth. Anyone who can reach the
// listener can issue a certificate.
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

		profile, ok := profiles.Lookup(req.Profile)
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
		cert, err := pki.IssueLeaf(profile, csr.Subject, csr.PublicKey,
			deps.IntermediateIssuer, now, now.Add(profile.Validity), csr.DNSNames)
		if err != nil {
			deps.Logger.Error("issuing certificate failed", "profile", profile.Name, "err", err)
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
			deps.Logger.Error("persisting issued certificate failed", "serial", rec.Serial, "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if err := deps.Store.Audit().Append(r.Context(), store.AuditEntry{
			Timestamp: now.UTC(),
			Actor:     r.RemoteAddr,
			Action:    "issue",
			Target:    rec.Serial,
			Detail:    profile.Name,
		}); err != nil {
			deps.Logger.Error("writing audit entry failed", "serial", rec.Serial, "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		writeJSON(w, http.StatusCreated, issueCertificateResponse{
			Serial:    rec.Serial,
			Profile:   profile.Name,
			NotBefore: cert.NotBefore,
			NotAfter:  cert.NotAfter,
			PEM:       string(rec.PEM),
		})
	}
}

type certificateResponse struct {
	Serial       string    `json:"serial"`
	Kind         string    `json:"kind"`
	Profile      string    `json:"profile"`
	Subject      string    `json:"subject"`
	IssuerSerial string    `json:"issuer_serial"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	PEM          string    `json:"pem"`
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
			Serial:       rec.Serial,
			Kind:         string(rec.Kind),
			Profile:      rec.ProfileName,
			Subject:      rec.Subject,
			IssuerSerial: rec.IssuerSerial,
			NotBefore:    rec.NotBefore,
			NotAfter:     rec.NotAfter,
			PEM:          string(rec.PEM),
		})
	}
}
