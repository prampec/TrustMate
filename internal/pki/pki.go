// Package pki is the CA core: certificate issuance logic. It takes a
// profile, a subject, and a public key (or generates the keypair
// server-side) and produces a signed certificate. Always enabled -- see
// docs/design.md, module 1.
package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// serialBytes follows RFC 5280 / CA/Browser Forum baseline practice:
// unguessable serials with at least 64 bits of CSPRNG entropy.
const serialBytes = 20

// GenerateSerial returns a random, RFC 5280-positive certificate serial
// number (the top bit is cleared so the big-endian byte slice never
// encodes as a negative ASN.1 INTEGER).
func GenerateSerial() (*big.Int, error) {
	buf := make([]byte, serialBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("pki: generating serial: %w", err)
	}
	buf[0] &= 0x7F
	return new(big.Int).SetBytes(buf), nil
}

// CertRequest carries everything needed to build an x509.Certificate
// template. Empty URL fields omit the corresponding extension.
type CertRequest struct {
	Subject   pkix.Name
	PublicKey crypto.PublicKey

	NotBefore, NotAfter time.Time

	IsCA        bool
	PathLenZero bool // intermediate: pathlen=0, no further sub-CAs in Phase 0

	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage
	DNSNames    []string

	AIAIssuerURL string // caIssuers; "" omits the extension
	OCSPURL      string // "" omits the extension
	CRLURL       string // "" omits the extension
}

// Issuer bundles a signing certificate with its private key.
type Issuer struct {
	Cert   *x509.Certificate
	Signer crypto.Signer
}

func buildTemplate(req CertRequest) (*x509.Certificate, error) {
	serial, err := GenerateSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               req.Subject,
		NotBefore:             req.NotBefore,
		NotAfter:              req.NotAfter,
		KeyUsage:              req.KeyUsage,
		ExtKeyUsage:           req.ExtKeyUsage,
		DNSNames:              req.DNSNames,
		BasicConstraintsValid: true,
		IsCA:                  req.IsCA,
	}
	if req.IsCA && req.PathLenZero {
		tmpl.MaxPathLen = 0
		tmpl.MaxPathLenZero = true
	}
	if req.AIAIssuerURL != "" {
		tmpl.IssuingCertificateURL = []string{req.AIAIssuerURL}
	}
	if req.OCSPURL != "" {
		tmpl.OCSPServer = []string{req.OCSPURL}
	}
	if req.CRLURL != "" {
		tmpl.CRLDistributionPoints = []string{req.CRLURL}
	}
	return tmpl, nil
}
