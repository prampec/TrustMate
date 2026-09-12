package revocation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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
	_, inter := testRootAndIntermediateIssuers(t)
	return inter
}

func testRootAndIntermediateIssuers(t *testing.T) (root, inter pki.Issuer) {
	t.Helper()
	rootSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootCert, err := pki.SelfSignedCA(pki.CertRequest{
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
	interCert, err := pki.IssueCA(pki.CertRequest{
		Subject:     pkix.Name{CommonName: "Test Intermediate"},
		PublicKey:   interSigner.Public(),
		NotBefore:   now,
		NotAfter:    now.Add(time.Hour),
		IsCA:        true,
		PathLenZero: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, pki.Issuer{Cert: rootCert, Signer: rootSigner})
	if err != nil {
		t.Fatalf("IssueCA: %v", err)
	}
	return pki.Issuer{Cert: rootCert, Signer: rootSigner}, pki.Issuer{Cert: interCert, Signer: interSigner}
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

// TestCRLBuilderScopesEntriesToOwnIssuer verifies each CA's CRL only
// lists revocations of certificates it itself issued: the root's CRL
// must carry the revoked intermediate but not the revoked leaf (issued
// by the intermediate), and vice versa -- a CRLDP that names the wrong
// CA's CRL is an RFC 5280 violation (see internal/bootstrap/bootstrap.go's
// generateIntermediate, which points the intermediate cert's own CDP at
// the root's CRL, not its own).
func TestCRLBuilderScopesEntriesToOwnIssuer(t *testing.T) {
	root, inter := testRootAndIntermediateIssuers(t)
	certs := testCertRepo(t)

	if err := certs.Create(context.Background(), store.CertificateRecord{
		Serial:    root.Cert.SerialNumber.String(),
		Kind:      store.CertKindRoot,
		Subject:   root.Cert.Subject.String(),
		NotBefore: root.Cert.NotBefore,
		NotAfter:  root.Cert.NotAfter,
		PEM:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Cert.Raw}),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Certificates().Create(root): %v", err)
	}
	if err := certs.Create(context.Background(), store.CertificateRecord{
		Serial:       inter.Cert.SerialNumber.String(),
		Kind:         store.CertKindIntermediate,
		Subject:      inter.Cert.Subject.String(),
		IssuerSerial: root.Cert.SerialNumber.String(),
		NotBefore:    inter.Cert.NotBefore,
		NotAfter:     inter.Cert.NotAfter,
		PEM:          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter.Cert.Raw}),
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Certificates().Create(intermediate): %v", err)
	}
	if err := certs.Revoke(context.Background(), inter.Cert.SerialNumber.String(), "cessationOfOperation", time.Now()); err != nil {
		t.Fatalf("Revoke(intermediate): %v", err)
	}

	leaf := testLeaf(t, inter, "revoked-leaf")
	if err := certs.Create(context.Background(), store.CertificateRecord{
		Serial:       leaf.SerialNumber.String(),
		Kind:         store.CertKindLeaf,
		Subject:      leaf.Subject.String(),
		IssuerSerial: inter.Cert.SerialNumber.String(),
		NotBefore:    leaf.NotBefore,
		NotAfter:     leaf.NotAfter,
		PEM:          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Certificates().Create(leaf): %v", err)
	}
	if err := certs.Revoke(context.Background(), leaf.SerialNumber.String(), "keyCompromise", time.Now()); err != nil {
		t.Fatalf("Revoke(leaf): %v", err)
	}

	rootCRL := parseCRL(t, NewCRLBuilder(root, certs))
	if err := rootCRL.CheckSignatureFrom(root.Cert); err != nil {
		t.Errorf("root CRL does not verify against root: %v", err)
	}
	assertEntrySerials(t, rootCRL, inter.Cert.SerialNumber)

	interCRL := parseCRL(t, NewCRLBuilder(inter, certs))
	if err := interCRL.CheckSignatureFrom(inter.Cert); err != nil {
		t.Errorf("intermediate CRL does not verify against intermediate: %v", err)
	}
	assertEntrySerials(t, interCRL, leaf.SerialNumber)
}

func parseCRL(t *testing.T, b *CRLBuilder) *x509.RevocationList {
	t.Helper()
	der, err := b.CRL(context.Background())
	if err != nil {
		t.Fatalf("CRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	return crl
}

func assertEntrySerials(t *testing.T, crl *x509.RevocationList, want ...*big.Int) {
	t.Helper()
	if len(crl.RevokedCertificateEntries) != len(want) {
		t.Fatalf("RevokedCertificateEntries = %v, want %d entries matching %v", crl.RevokedCertificateEntries, len(want), want)
	}
	for i, w := range want {
		if crl.RevokedCertificateEntries[i].SerialNumber.Cmp(w) != 0 {
			t.Errorf("entry %d serial = %v, want %v", i, crl.RevokedCertificateEntries[i].SerialNumber, w)
		}
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
