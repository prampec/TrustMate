package pki

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParseCSR decodes a PKCS#10 certificate signing request (PEM or raw DER)
// and verifies its self-signature, proving possession of the private key
// for the embedded public key. Callers read Subject/PublicKey/DNSNames
// off the returned stdlib type directly -- picking which of those fields
// to honor when issuing is the caller's policy decision, not pki's.
func ParseCSR(data []byte) (*x509.CertificateRequest, error) {
	der := data
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parsing CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: CSR signature verification failed: %w", err)
	}
	return csr, nil
}
