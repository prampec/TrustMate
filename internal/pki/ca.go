package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SKI computation (RFC 5280 method 1), not used for security
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// SelfSignedCA issues a self-signed root CA certificate. req.IsCA and
// req.KeyUsage are expected to already carry CA-appropriate values
// (CA:true, KeyUsageCertSign|KeyUsageCRLSign); this function does not
// second-guess the caller's request, it only fills in the Subject Key
// Identifier and performs the self-signing.
func SelfSignedCA(req CertRequest, signer crypto.Signer) (*x509.Certificate, error) {
	req.PublicKey = signer.Public()
	tmpl, err := buildTemplate(req)
	if err != nil {
		return nil, err
	}

	ski, err := subjectKeyID(req.PublicKey)
	if err != nil {
		return nil, err
	}
	tmpl.SubjectKeyId = ski
	tmpl.AuthorityKeyId = ski // self-signed: authority == subject

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, req.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("pki: creating self-signed CA certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

// IssueCA issues an intermediate CA certificate signed by issuer.
func IssueCA(req CertRequest, issuer Issuer) (*x509.Certificate, error) {
	tmpl, err := buildTemplate(req)
	if err != nil {
		return nil, err
	}

	ski, err := subjectKeyID(req.PublicKey)
	if err != nil {
		return nil, err
	}
	tmpl.SubjectKeyId = ski
	tmpl.AuthorityKeyId = issuer.Cert.SubjectKeyId

	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer.Cert, req.PublicKey, issuer.Signer)
	if err != nil {
		return nil, fmt.Errorf("pki: creating intermediate CA certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

// subjectKeyID computes the Subject Key Identifier per RFC 5280 section
// 4.2.1.2 method (1): the SHA-1 hash of the BIT STRING subjectPublicKey
// (excluding tag, length, and number-of-unused-bits octet). Computed
// explicitly rather than relying on x509.CreateCertificate's own
// (version-dependent) default-population behavior.
func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("pki: marshalling public key: %w", err)
	}
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("pki: parsing SubjectPublicKeyInfo: %w", err)
	}
	sum := sha1.Sum(spki.PublicKey.Bytes)
	return sum[:], nil
}
