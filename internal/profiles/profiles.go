// Package profiles holds certificate profile definitions (key usage, EKU,
// validity, AIA/CDP/OCSP URL templates, SAN rules) as versioned
// config/code rather than database rows edited through a UI. See
// docs/design.md, module 4.
package profiles

import (
	"crypto/x509"
	"time"

	"github.com/prampec/trustmate/internal/keystore"
)

// Profile is a leaf-certificate issuance policy. Root/intermediate CA
// generation does not go through a Profile -- their BasicConstraints/
// pathlen/KeyUsage are structural and handled directly by internal/pki's
// CA-specific functions.
type Profile struct {
	Name         string
	Version      int
	KeyAlgorithm keystore.Algorithm
	KeyUsage     x509.KeyUsage
	ExtKeyUsage  []x509.ExtKeyUsage
	// CriticalEKU marks the Extended Key Usage extension critical (RFC
	// 3161 section 2.3 requires this for a TSA signing certificate; no
	// other built-in profile needs it).
	CriticalEKU bool
	Validity    time.Duration

	EnableOCSP bool
	EnableCRL  bool

	// URL templates for AIA caIssuers / CRL distribution point / AIA OCSP.
	// Populated with the deployment's actual base URL at issuance time.
	AIATemplate  string
	CDPTemplate  string
	OCSPTemplate string
}

// Default is the profile used for the bootstrap admin REST access
// certificate: client-auth, short-lived relative to the CAs, no
// CRL/OCSP (the admin cert isn't expected to be revoked through the
// not-yet-existing revocation module in Phase 0).
func Default() Profile {
	return Profile{
		Name:         "default",
		Version:      1,
		KeyAlgorithm: keystore.AlgorithmECDSAP256,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Validity:     365 * 24 * time.Hour,
	}
}

// ServerTLS is the profile used for the bootstrap server TLS
// certificate: the REST API's own HTTPS listener identity.
func ServerTLS() Profile {
	return Profile{
		Name:         "server-tls",
		Version:      1,
		KeyAlgorithm: keystore.AlgorithmECDSAP256,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Validity:     365 * 24 * time.Hour,
	}
}

// DocumentSigning is Phase 1's example profile for CSR-driven issuance
// via POST /v1/certificates -- see docs/design.md's Phase 1 roadmap
// entry. No specific ExtKeyUsage: this is illustrative, not a
// compliance-grade document-signing spec.
func DocumentSigning() Profile {
	return Profile{
		Name:         "document-signing",
		Version:      1,
		KeyAlgorithm: keystore.AlgorithmECDSAP256,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		Validity:     2 * 365 * 24 * time.Hour,
		EnableOCSP:   true,
		EnableCRL:    true,
	}
}

// TSA is the profile used for the bootstrap-issued RFC 3161 Time-Stamp
// Authority signing identity -- its own certificate, distinct from the
// intermediate CA (see docs/design.md's tsa module entry). Per RFC 3161
// section 2.3 the Extended Key Usage extension must be critical and
// contain only id-kp-timeStamping.
func TSA() Profile {
	return Profile{
		Name:         "tsa",
		Version:      1,
		KeyAlgorithm: keystore.AlgorithmECDSAP256,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		CriticalEKU:  true,
	}
}

// All returns every built-in profile.
func All() []Profile {
	return []Profile{Default(), ServerTLS(), DocumentSigning(), TSA()}
}

// Lookup finds a built-in profile by name.
func Lookup(name string) (Profile, bool) {
	for _, p := range All() {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}

// WithIssuerURLs returns a copy of p with its AIA/CDP/OCSP URL templates
// populated from baseURL, the deployment's public origin. AIA caIssuers
// is always set (per docs/design.md's table: "on every non-root cert");
// CDP/AIA-OCSP are set only when both revocationEnabled (the revocation
// module is on at all) and the profile's own EnableCRL/EnableOCSP (this
// class of certificate wants that extension) are true -- two independent
// gates, mirroring internal/bootstrap's existing module-gating pattern.
func (p Profile) WithIssuerURLs(baseURL string, revocationEnabled bool) Profile {
	p.AIATemplate = baseURL + "/v1/ca/intermediate.pem"
	if revocationEnabled && p.EnableCRL {
		p.CDPTemplate = baseURL + "/v1/crl/intermediate.crl"
	}
	if revocationEnabled && p.EnableOCSP {
		p.OCSPTemplate = baseURL + "/v1/ocsp"
	}
	return p
}
