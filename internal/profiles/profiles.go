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
	Validity     time.Duration

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
