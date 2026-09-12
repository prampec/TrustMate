package api

import (
	"log/slog"

	"github.com/prampec/trustmate/internal/pki"
	"github.com/prampec/trustmate/internal/revocation"
	"github.com/prampec/trustmate/internal/store"
)

// Deps carries every dependency the REST handlers need. Grouping them
// here means NewRouter's signature doesn't grow a new positional
// parameter per feature.
type Deps struct {
	Logger *slog.Logger
	Store  store.Store

	// IntermediateIssuer signs every leaf certificate issued via
	// POST /v1/certificates.
	IntermediateIssuer pki.Issuer
	// PublicBaseURL is this deployment's externally reachable origin,
	// templated into AIA/CDP/OCSP extensions on newly issued leaves.
	PublicBaseURL string

	ModuleConfig ModuleConfig

	CRLBuilder    *revocation.CRLBuilder
	OCSPResponder *revocation.OCSPResponder
}
