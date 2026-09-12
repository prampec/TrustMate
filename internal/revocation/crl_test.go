package revocation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/prampec/trustmate/internal/pki"
)

func testIssuer(t *testing.T) pki.Issuer {
	t.Helper()
	rootSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root, err := pki.SelfSignedCA(pki.CertRequest{
		Subject:   pkix.Name{CommonName: "Test Root"},
		NotBefore: now,
		NotAfter:  now.Add(24 * time.Hour),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, rootSigner)
	if err != nil {
		t.Fatalf("SelfSignedCA: %v", err)
	}

	interSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := pki.IssueCA(pki.CertRequest{
		Subject:     pkix.Name{CommonName: "Test Intermediate"},
		PublicKey:   interSigner.Public(),
		NotBefore:   now,
		NotAfter:    now.Add(time.Hour),
		IsCA:        true,
		PathLenZero: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, pki.Issuer{Cert: root, Signer: rootSigner})
	if err != nil {
		t.Fatalf("IssueCA: %v", err)
	}
	return pki.Issuer{Cert: inter, Signer: interSigner}
}

func TestCRLBuilderProducesVerifiableEmptyCRL(t *testing.T) {
	issuer := testIssuer(t)
	b := NewCRLBuilder(issuer)

	der, err := b.CRL(context.Background())
	if err != nil {
		t.Fatalf("CRL: %v", err)
	}

	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if err := crl.CheckSignatureFrom(issuer.Cert); err != nil {
		t.Errorf("CRL does not verify against issuer: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Errorf("RevokedCertificateEntries = %v, want empty", crl.RevokedCertificateEntries)
	}
	if !crl.NextUpdate.After(crl.ThisUpdate) {
		t.Errorf("NextUpdate %v is not after ThisUpdate %v", crl.NextUpdate, crl.ThisUpdate)
	}
}

func TestCRLBuilderCachesWithinValidity(t *testing.T) {
	issuer := testIssuer(t)
	b := NewCRLBuilder(issuer)

	first, err := b.CRL(context.Background())
	if err != nil {
		t.Fatalf("CRL: %v", err)
	}
	second, err := b.CRL(context.Background())
	if err != nil {
		t.Fatalf("CRL: %v", err)
	}
	if string(first) != string(second) {
		t.Error("two CRL() calls within the validity window returned different bytes, want a cache hit")
	}
}
