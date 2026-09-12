package tsa

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	"github.com/prampec/trustmate/internal/keystore"
	"github.com/prampec/trustmate/internal/pki"
	"github.com/prampec/trustmate/internal/store"
	"github.com/prampec/trustmate/internal/store/sqlite"
)

func testInterIssuer(t *testing.T) pki.Issuer {
	t.Helper()
	rootSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root, err := pki.SelfSignedCA(pki.CertRequest{
		Subject: pkix.Name{CommonName: "Test Root"}, NotBefore: now, NotAfter: now.Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, rootSigner)
	if err != nil {
		t.Fatalf("SelfSignedCA: %v", err)
	}

	interSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := pki.IssueCA(pki.CertRequest{
		Subject: pkix.Name{CommonName: "Test Intermediate"}, PublicKey: interSigner.Public(),
		NotBefore: now, NotAfter: now.Add(time.Hour), IsCA: true, PathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, pki.Issuer{Cert: root, Signer: rootSigner})
	if err != nil {
		t.Fatalf("IssueCA: %v", err)
	}
	return pki.Issuer{Cert: inter, Signer: interSigner}
}

// persistIntermediate inserts inter's certificate row -- required before
// IssueIdentity, since the certificates table's issuer_serial column is a
// foreign key referencing certificates(serial).
func persistIntermediate(t *testing.T, st store.Store, inter pki.Issuer) {
	t.Helper()
	if err := st.Certificates().Create(context.Background(), store.CertificateRecord{
		Serial:    inter.Cert.SerialNumber.String(),
		Kind:      store.CertKindIntermediate,
		Subject:   inter.Cert.Subject.String(),
		NotBefore: inter.Cert.NotBefore,
		NotAfter:  inter.Cert.NotAfter,
		PEM:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter.Cert.Raw}),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Certificates().Create(intermediate): %v", err)
	}
}

func TestIssueIdentityChainsAndPersists(t *testing.T) {
	ctx := context.Background()
	inter := testInterIssuer(t)

	st, err := sqlite.Open(filepath.Join(t.TempDir(), "trustmate.db"))
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	ks, err := keystore.NewFileKeyStore(filepath.Join(t.TempDir(), "keys"), []byte("test-passphrase"))
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}
	persistIntermediate(t, st, inter)

	issuer, rec, err := IssueIdentity(ctx, "tsa-test", IdentityParams{
		CommonName: "Test TSA", Validity: time.Hour, PublicBaseURL: "https://ca.example.test",
	}, st, ks, inter)
	if err != nil {
		t.Fatalf("IssueIdentity: %v", err)
	}

	if err := issuer.Cert.CheckSignatureFrom(inter.Cert); err != nil {
		t.Errorf("issued TSA cert does not chain to intermediate: %v", err)
	}
	if len(issuer.Cert.ExtKeyUsage) != 1 || issuer.Cert.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping {
		t.Errorf("ExtKeyUsage = %v, want exactly {ExtKeyUsageTimeStamping}", issuer.Cert.ExtKeyUsage)
	}
	if rec.KeyRef != "tsa-test" {
		t.Errorf("KeyRef = %q, want %q", rec.KeyRef, "tsa-test")
	}
	if rec.ProfileName != "tsa" {
		t.Errorf("ProfileName = %q, want %q", rec.ProfileName, "tsa")
	}
	if rec.Serial != issuer.Cert.SerialNumber.String() {
		t.Errorf("rec.Serial = %q, want %q", rec.Serial, issuer.Cert.SerialNumber.String())
	}

	stored, err := st.Certificates().GetBySerial(ctx, rec.Serial)
	if err != nil {
		t.Fatalf("GetBySerial: %v", err)
	}
	if stored.KeyRef != "tsa-test" {
		t.Errorf("stored KeyRef = %q, want %q", stored.KeyRef, "tsa-test")
	}

	signer, err := ks.Get(ctx, "tsa-test")
	if err != nil {
		t.Fatalf("ks.Get(tsa-test): %v", err)
	}
	if !signer.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(issuer.Cert.PublicKey) {
		t.Error("keystore signer's public key does not match the issued certificate's public key")
	}
}

func TestIssueIdentityRefusesToOverwriteExistingRef(t *testing.T) {
	ctx := context.Background()
	inter := testInterIssuer(t)

	st, err := sqlite.Open(filepath.Join(t.TempDir(), "trustmate.db"))
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	ks, err := keystore.NewFileKeyStore(filepath.Join(t.TempDir(), "keys"), []byte("test-passphrase"))
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}
	persistIntermediate(t, st, inter)

	params := IdentityParams{CommonName: "Test TSA", Validity: time.Hour, PublicBaseURL: "https://ca.example.test"}
	if _, _, err := IssueIdentity(ctx, "tsa-dup", params, st, ks, inter); err != nil {
		t.Fatalf("first IssueIdentity: %v", err)
	}
	if _, _, err := IssueIdentity(ctx, "tsa-dup", params, st, ks, inter); err == nil {
		t.Error("second IssueIdentity with the same ref succeeded, want an error")
	}
}
