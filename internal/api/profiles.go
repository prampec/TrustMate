package api

import (
	"net/http"
	"time"

	"github.com/prampec/trustmate/internal/profiles"
	"github.com/prampec/trustmate/internal/store"
)

type profileResponse struct {
	Name        string   `json:"name"`
	Version     int      `json:"version"`
	KeyUsage    []string `json:"key_usage"`
	ExtKeyUsage []string `json:"ext_key_usage"`
	CriticalEKU bool     `json:"critical_eku"`
	Validity    string   `json:"validity"`
	EnableOCSP  bool     `json:"enable_ocsp"`
	EnableCRL   bool     `json:"enable_crl"`
}

func toProfileResponse(p profiles.Profile) profileResponse {
	return profileResponse{
		Name:        p.Name,
		Version:     p.Version,
		KeyUsage:    keyUsageStrings(p),
		ExtKeyUsage: extKeyUsageStrings(p),
		CriticalEKU: p.CriticalEKU,
		Validity:    p.Validity.String(),
		EnableOCSP:  p.EnableOCSP,
		EnableCRL:   p.EnableCRL,
	}
}

func keyUsageStrings(p profiles.Profile) []string {
	names := []struct {
		bit  int
		name string
	}{
		{1 << 0, "digitalSignature"},
		{1 << 1, "contentCommitment"},
		{1 << 2, "keyEncipherment"},
		{1 << 3, "dataEncipherment"},
		{1 << 4, "keyAgreement"},
		{1 << 5, "certSign"},
		{1 << 6, "crlSign"},
		{1 << 7, "encipherOnly"},
		{1 << 8, "decipherOnly"},
	}
	var out []string
	for _, n := range names {
		if int(p.KeyUsage)&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

func extKeyUsageStrings(p profiles.Profile) []string {
	var names = map[int]string{
		1: "serverAuth",
		2: "clientAuth",
		3: "codeSigning",
		4: "emailProtection",
		8: "timeStamping",
		9: "ocspSigning",
	}
	out := make([]string, 0, len(p.ExtKeyUsage))
	for _, eku := range p.ExtKeyUsage {
		if name, ok := names[int(eku)]; ok {
			out = append(out, name)
		}
	}
	return out
}

// handleListProfiles requires manager (or admin) role: a caller needs to
// see what profiles exist to pick one when issuing.
func handleListProfiles(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var all []profiles.Profile
		if deps.Profiles != nil {
			all = deps.Profiles.All()
		} else {
			all = profiles.All()
		}
		out := make([]profileResponse, 0, len(all))
		for _, p := range all {
			out = append(out, toProfileResponse(p))
		}
		writeJSON(w, http.StatusOK, out)
	}
}

type reloadProfilesResponse struct {
	Profiles []string `json:"profiles"`
}

// handleReloadProfiles re-scans TRUSTMATE_PROFILES_DIR without a restart.
// Requires admin role -- this alters what a manager can subsequently
// issue, which is configuration, not certificate operations.
func handleReloadProfiles(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.Profiles == nil {
			writeError(w, http.StatusServiceUnavailable, "profile registry not configured")
			return
		}
		if err := deps.Profiles.Load(r.Context()); err != nil {
			deps.Logger.Error("reloading profiles failed", "err", err)
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		all := deps.Profiles.All()
		names := make([]string, 0, len(all))
		for _, p := range all {
			names = append(names, p.Name)
		}

		if err := deps.Store.Audit().Append(r.Context(), store.AuditEntry{
			Timestamp: time.Now().UTC(),
			Actor:     r.RemoteAddr,
			Action:    "profiles-reload",
			Detail:    "",
		}); err != nil {
			deps.Logger.Error("writing audit entry failed", "err", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		writeJSON(w, http.StatusOK, reloadProfilesResponse{Profiles: names})
	}
}
