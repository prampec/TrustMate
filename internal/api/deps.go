package api

import (
	"log/slog"
	"time"

	"github.com/prampec/trustmate/internal/keystore"
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

	// InstanceName identifies this deployment -- surfaced in /healthz and
	// /readyz responses so an operator curling one of several replicas
	// (or instances) can tell which one answered. Empty in tests that
	// don't care about it.
	InstanceName string

	// IntermediateIssuer signs every leaf certificate issued via
	// POST /v1/certificates, POST /v1/clients, and POST /v1/tsa/rotate.
	IntermediateIssuer pki.Issuer
	// PublicBaseURL is this deployment's externally reachable origin,
	// templated into AIA/CDP/OCSP extensions on newly issued leaves.
	PublicBaseURL string

	// KeyStore generates the signing key for a newly rotated TSA identity
	// (POST /v1/tsa/rotate). Nil in tests that don't exercise that route.
	KeyStore keystore.KeyStore
	// TSACommonName and TSAValidity are the identity template a rotated
	// TSA certificate is issued against -- the same values the first-ever
	// TSA identity used at bootstrap (cfg.TSACommonName()/
	// cfg.Bootstrap.TSAValidity), so rotation mints a like-for-like
	// replacement.
	TSACommonName string
	TSAValidity   time.Duration

	ModuleConfig ModuleConfig

	// Profiles is the lookup source for POST /v1/certificates and GET
	// /v1/profiles -- built-ins plus anything loaded from
	// TRUSTMATE_PROFILES_DIR. Nil in tests that don't exercise those
	// routes falls back to the package-level built-ins (see profilesOf).
	Profiles *profiles.Registry

	// Metrics is nil in tests that don't care about it; handlers must
	// nil-check before recording.
	Metrics *observability.Metrics

	// CRLBuilder serves the intermediate CA's CRL (leaf-certificate
	// revocations); RootCRLBuilder serves the root CA's CRL (revocations
	// of certificates the root itself issued, i.e. the intermediate) --
	// see internal/revocation/crl.go's per-CA issuer-serial filtering.
	CRLBuilder     *revocation.CRLBuilder
	RootCRLBuilder *revocation.CRLBuilder
	OCSPResponder  *revocation.OCSPResponder
	TSAResponder   *tsa.Responder
}
