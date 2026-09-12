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
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// oidExtKeyUsage is the Extended Key Usage extension's OID (RFC 5280
// section 4.2.1.12). crypto/x509 does not export it.
var oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

// extKeyUsageOIDs maps the subset of x509.ExtKeyUsage values this package
// needs to build a hand-marshalled (critical) EKU extension with -- see
// CertRequest.CriticalExtKeyUsage. crypto/x509 keeps its own copy of this
// table unexported.
var extKeyUsageOIDs = map[x509.ExtKeyUsage]asn1.ObjectIdentifier{
	x509.ExtKeyUsageServerAuth:      {1, 3, 6, 1, 5, 5, 7, 3, 1},
	x509.ExtKeyUsageClientAuth:      {1, 3, 6, 1, 5, 5, 7, 3, 2},
	x509.ExtKeyUsageCodeSigning:     {1, 3, 6, 1, 5, 5, 7, 3, 3},
	x509.ExtKeyUsageEmailProtection: {1, 3, 6, 1, 5, 5, 7, 3, 4},
	x509.ExtKeyUsageTimeStamping:    {1, 3, 6, 1, 5, 5, 7, 3, 8},
	x509.ExtKeyUsageOCSPSigning:     {1, 3, 6, 1, 5, 5, 7, 3, 9},
}

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
	// CriticalExtKeyUsage marks the Extended Key Usage extension critical
	// instead of crypto/x509's hardcoded non-critical marshalling --
	// RFC 3161 section 2.3 requires this (and exactly one EKU value) for
	// a TSA signing certificate.
	CriticalExtKeyUsage bool
	DNSNames            []string

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
		DNSNames:              req.DNSNames,
		BasicConstraintsValid: true,
		IsCA:                  req.IsCA,
	}
	if req.CriticalExtKeyUsage {
		oids := make([]asn1.ObjectIdentifier, len(req.ExtKeyUsage))
		for i, eku := range req.ExtKeyUsage {
			oid, ok := extKeyUsageOIDs[eku]
			if !ok {
				return nil, fmt.Errorf("pki: no OID mapping for ExtKeyUsage %v", eku)
			}
			oids[i] = oid
		}
		ekuDER, err := asn1.Marshal(oids)
		if err != nil {
			return nil, fmt.Errorf("pki: marshalling critical ExtKeyUsage: %w", err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id:       oidExtKeyUsage,
			Critical: true,
			Value:    ekuDER,
		})
	} else {
		tmpl.ExtKeyUsage = req.ExtKeyUsage
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
