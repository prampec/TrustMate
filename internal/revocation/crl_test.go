package revocation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	"github.com/prampec/trustmate/internal/pki"
	"github.com/prampec/trustmate/internal/store"
	"github.com/prampec/trustmate/internal/store/sqlite"
)

func testCertRepo(t *testing.T) store.CertificateRepository {
	t.Helper()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "trustmate.db"))
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st.Certificates()
}

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
	b := NewCRLBuilder(issuer, testCertRepo(t))

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

func TestCRLBuilderListsRevokedEntriesAndInvalidate(t *testing.T) {
	issuer := testIssuer(t)
	certs := testCertRepo(t)
	b := NewCRLBuilder(issuer, certs)

	if err := certs.Create(context.Background(), store.CertificateRecord{
		Serial:    issuer.Cert.SerialNumber.String(),
		Kind:      store.CertKindIntermediate,
		Subject:   issuer.Cert.Subject.String(),
		NotBefore: issuer.Cert.NotBefore,
		NotAfter:  issuer.Cert.NotAfter,
		PEM:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Cert.Raw}),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Certificates().Create(intermediate): %v", err)
	}

	leaf := testLeaf(t, issuer, "revoked-leaf")
	if err := certs.Create(context.Background(), store.CertificateRecord{
		Serial:       leaf.SerialNumber.String(),
		Kind:         store.CertKindLeaf,
		Subject:      leaf.Subject.String(),
		IssuerSerial: issuer.Cert.SerialNumber.String(),
		NotBefore:    leaf.NotBefore,
		NotAfter:     leaf.NotAfter,
		PEM:          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Certificates().Create: %v", err)
	}

	first, err := b.CRL(context.Background())
	if err != nil {
		t.Fatalf("CRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(first)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Fatalf("RevokedCertificateEntries before revoke = %v, want empty", crl.RevokedCertificateEntries)
	}

	if err := certs.Revoke(context.Background(), leaf.SerialNumber.String(), "keyCompromise", time.Now()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Without Invalidate, the cached (pre-revoke) CRL would still be
	// returned within CRLValidity -- exercise that Invalidate actually
	// forces regeneration.
	b.Invalidate()

	second, err := b.CRL(context.Background())
	if err != nil {
		t.Fatalf("CRL after revoke: %v", err)
	}
	crl, err = x509.ParseRevocationList(second)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if err := crl.CheckSignatureFrom(issuer.Cert); err != nil {
		t.Errorf("CRL does not verify against issuer: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 {
		t.Fatalf("RevokedCertificateEntries = %v, want 1 entry", crl.RevokedCertificateEntries)
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Errorf("revoked entry serial = %v, want %v", crl.RevokedCertificateEntries[0].SerialNumber, leaf.SerialNumber)
	}
}

func TestCRLBuilderCachesWithinValidity(t *testing.T) {
	issuer := testIssuer(t)
	b := NewCRLBuilder(issuer, testCertRepo(t))

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
