package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	"github.com/prampec/trustmate/internal/profiles"
)

// IssueLeaf issues a leaf certificate against profile, signed by issuer.
// AIA caIssuers is always set (per docs/design.md's table: "on every
// non-root cert"); CRL/OCSP extensions are set only when the profile
// enables them.
func IssueLeaf(profile profiles.Profile, subject pkix.Name, pub crypto.PublicKey, issuer Issuer, notBefore, notAfter time.Time, dnsNames []string) (*x509.Certificate, error) {
	req := CertRequest{
		Subject:      subject,
		PublicKey:    pub,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		IsCA:         false,
		KeyUsage:     profile.KeyUsage,
		ExtKeyUsage:  profile.ExtKeyUsage,
		DNSNames:     dnsNames,
		AIAIssuerURL: profile.AIATemplate,
	}
	if profile.EnableCRL {
		req.CRLURL = profile.CDPTemplate
	}
	if profile.EnableOCSP {
		req.OCSPURL = profile.OCSPTemplate
	}

	tmpl, err := buildTemplate(req)
	if err != nil {
		return nil, err
	}

	ski, err := subjectKeyID(pub)
	if err != nil {
		return nil, err
	}
	tmpl.SubjectKeyId = ski
	tmpl.AuthorityKeyId = issuer.Cert.SubjectKeyId

	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer.Cert, pub, issuer.Signer)
	if err != nil {
		return nil, fmt.Errorf("pki: creating leaf certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}
