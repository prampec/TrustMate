package api

import (
	"log/slog"

	"github.com/prampec/trustmate/internal/observability"
	"github.com/prampec/trustmate/internal/pki"
	"github.com/prampec/trustmate/internal/profiles"
	"github.com/prampec/trustmate/internal/revocation"
	"github.com/prampec/trustmate/internal/store"
	"github.com/prampec/trustmate/internal/tsa"
)

// Deps carries every dependency the REST handlers need. Grouping them
// here means NewRouter's signature doesn't grow a new positional
// parameter per feature.
type Deps struct {
	Logger *slog.Logger
	Store  store.Store

	// IntermediateIssuer signs every leaf certificate issued via
	// POST /v1/certificates and POST /v1/clients.
	IntermediateIssuer pki.Issuer
	// PublicBaseURL is this deployment's externally reachable origin,
	// templated into AIA/CDP/OCSP extensions on newly issued leaves.
	PublicBaseURL string

	ModuleConfig ModuleConfig

	// Profiles is the lookup source for POST /v1/certificates and GET
	// /v1/profiles -- built-ins plus anything loaded from
	// TRUSTMATE_PROFILES_DIR. Nil in tests that don't exercise those
	// routes falls back to the package-level built-ins (see profilesOf).
	Profiles *profiles.Registry

	// Metrics is nil in tests that don't care about it; handlers must
	// nil-check before recording.
	Metrics *observability.Metrics

	CRLBuilder    *revocation.CRLBuilder
	OCSPResponder *revocation.OCSPResponder
	TSAResponder  *tsa.Responder
}
