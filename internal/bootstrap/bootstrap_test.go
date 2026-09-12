package bootstrap

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/prampec/trustmate/internal/config"
	"github.com/prampec/trustmate/internal/keystore"
	"github.com/prampec/trustmate/internal/store"
	"github.com/prampec/trustmate/internal/store/sqlite"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestStore(t *testing.T) store.Store {
	t.Helper()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "trustmate.db"))
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func newTestKeyStore(t *testing.T) keystore.KeyStore {
	t.Helper()
	ks, err := keystore.NewFileKeyStore(filepath.Join(t.TempDir(), "keys"), []byte("test-passphrase"))
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}
	return ks
}

func parseCertPEM(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("parseCertPEM: no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parseCertPEM: %v", err)
	}
	return cert
}

func TestRunGeneratesFourCertificatesAndBootstrapOutput(t *testing.T) {
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Bootstrap.OutputDir = filepath.Join(t.TempDir(), "bootstrap")
	st := newTestStore(t)
	ks := newTestKeyStore(t)

	result, err := Run(ctx, discardLogger(), cfg, st, ks)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.AlreadyBootstrapped {
		t.Error("first Run reported AlreadyBootstrapped = true, want false")
	}

	roots, err := st.Certificates().FindByKind(ctx, store.CertKindRoot)
	if err != nil || len(roots) != 1 {
		t.Fatalf("FindByKind(root) = %v, %v; want 1 row", roots, err)
	}
	inters, err := st.Certificates().FindByKind(ctx, store.CertKindIntermediate)
	if err != nil || len(inters) != 1 {
		t.Fatalf("FindByKind(intermediate) = %v, %v; want 1 row", inters, err)
	}
	leaves, err := st.Certificates().FindByKind(ctx, store.CertKindLeaf)
	if err != nil || len(leaves) != 2 {
		t.Fatalf("FindByKind(leaf) = %v, %v; want 2 rows (admin + server-tls)", leaves, err)
	}

	for _, name := range []string{"root.pem", "intermediate.pem", "chain.pem", "admin.pem", "admin-key.pem"} {
		path := filepath.Join(cfg.Bootstrap.OutputDir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected bootstrap output file %s: %v", path, err)
		}
	}
	// server-tls material must NOT be exported to disk -- the server
	// keeps custody of it via the keystore instead.
	if _, err := os.Stat(filepath.Join(cfg.Bootstrap.OutputDir, "server-tls.pem")); err == nil {
		t.Error("server-tls.pem was exported to bootstrap output dir, want it kept server-side only")
	}

	keyInfo, err := os.Stat(filepath.Join(cfg.Bootstrap.OutputDir, "admin-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("admin-key.pem perm = %o, want 0600", perm)
	}

	// Chain verifies: root -> intermediate -> each leaf.
	rootCert := parseCertPEM(t, roots[0].PEM)
	interCert := parseCertPEM(t, inters[0].PEM)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	interPool := x509.NewCertPool()
	interPool.AddCert(interCert)

	for _, leafRec := range leaves {
		leafCert := parseCertPEM(t, leafRec.PEM)
		if _, err := leafCert.Verify(x509.VerifyOptions{
			Roots:         rootPool,
			Intermediates: interPool,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			t.Errorf("leaf %s (profile %s) does not verify through intermediate to root: %v", leafRec.Serial, leafRec.ProfileName, err)
		}
	}
}

func TestRunIsIdempotentAndNeverCallsGenerateOnRestart(t *testing.T) {
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Bootstrap.OutputDir = filepath.Join(t.TempDir(), "bootstrap")
	st := newTestStore(t)
	ks := newTestKeyStore(t)

	if _, err := Run(ctx, discardLogger(), cfg, st, ks); err != nil {
		t.Fatalf("first Run: %v", err)
	}

	result, err := Run(ctx, discardLogger(), cfg, st, panicOnGenerate{KeyStore: ks})
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if !result.AlreadyBootstrapped {
		t.Error("second Run reported AlreadyBootstrapped = false, want true")
	}

	leaves, err := st.Certificates().FindByKind(ctx, store.CertKindLeaf)
	if err != nil || len(leaves) != 2 {
		t.Fatalf("FindByKind(leaf) after second Run = %v, %v; want still 2 rows", leaves, err)
	}
}

func TestRunUsesAbsolutePublicBaseURLInExtensions(t *testing.T) {
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Bootstrap.OutputDir = filepath.Join(t.TempDir(), "bootstrap")
	cfg.Server.PublicBaseURL = "https://ca.example.test"
	st := newTestStore(t)
	ks := newTestKeyStore(t)

	if _, err := Run(ctx, discardLogger(), cfg, st, ks); err != nil {
		t.Fatalf("Run: %v", err)
	}

	inters, err := st.Certificates().FindByKind(ctx, store.CertKindIntermediate)
	if err != nil || len(inters) != 1 {
		t.Fatalf("FindByKind(intermediate) = %v, %v; want 1 row", inters, err)
	}
	interCert := parseCertPEM(t, inters[0].PEM)
	if len(interCert.IssuingCertificateURL) != 1 || interCert.IssuingCertificateURL[0] != "https://ca.example.test/v1/ca/root.pem" {
		t.Errorf("intermediate IssuingCertificateURL = %v, want [https://ca.example.test/v1/ca/root.pem]", interCert.IssuingCertificateURL)
	}
	if len(interCert.CRLDistributionPoints) != 1 || interCert.CRLDistributionPoints[0] != "https://ca.example.test/v1/crl/intermediate.crl" {
		t.Errorf("intermediate CRLDistributionPoints = %v, want [https://ca.example.test/v1/crl/intermediate.crl]", interCert.CRLDistributionPoints)
	}
	if len(interCert.OCSPServer) != 1 || interCert.OCSPServer[0] != "https://ca.example.test/v1/ocsp" {
		t.Errorf("intermediate OCSPServer = %v, want [https://ca.example.test/v1/ocsp]", interCert.OCSPServer)
	}

	leaves, err := st.Certificates().FindByKind(ctx, store.CertKindLeaf)
	if err != nil || len(leaves) != 2 {
		t.Fatalf("FindByKind(leaf) = %v, %v; want 2 rows", leaves, err)
	}
	for _, rec := range leaves {
		cert := parseCertPEM(t, rec.PEM)
		if len(cert.IssuingCertificateURL) != 1 || cert.IssuingCertificateURL[0] != "https://ca.example.test/v1/ca/intermediate.pem" {
			t.Errorf("leaf %s IssuingCertificateURL = %v, want [https://ca.example.test/v1/ca/intermediate.pem]", rec.Serial, cert.IssuingCertificateURL)
		}
	}
}

func TestLoadIntermediateIssuerMatchesStoredCertAndKey(t *testing.T) {
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Bootstrap.OutputDir = filepath.Join(t.TempDir(), "bootstrap")
	st := newTestStore(t)
	ks := newTestKeyStore(t)

	if _, err := Run(ctx, discardLogger(), cfg, st, ks); err != nil {
		t.Fatalf("Run: %v", err)
	}

	issuer, err := LoadIntermediateIssuer(ctx, st, ks)
	if err != nil {
		t.Fatalf("LoadIntermediateIssuer: %v", err)
	}

	inters, err := st.Certificates().FindByKind(ctx, store.CertKindIntermediate)
	if err != nil || len(inters) != 1 {
		t.Fatalf("FindByKind(intermediate) = %v, %v; want 1 row", inters, err)
	}
	wantCert := parseCertPEM(t, inters[0].PEM)
	if issuer.Cert.SerialNumber.Cmp(wantCert.SerialNumber) != 0 {
		t.Errorf("issuer.Cert serial = %v, want %v", issuer.Cert.SerialNumber, wantCert.SerialNumber)
	}

	gotDER, err := x509.MarshalPKIXPublicKey(issuer.Signer.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey(signer): %v", err)
	}
	wantDER, err := x509.MarshalPKIXPublicKey(wantCert.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey(cert): %v", err)
	}
	if string(gotDER) != string(wantDER) {
		t.Error("issuer.Signer's public key does not match the stored intermediate certificate's public key")
	}
}

// panicOnGenerate wraps a KeyStore and panics if Generate is ever
// called, proving the idempotency short-circuit never touches the
// keystore on a restart.
type panicOnGenerate struct {
	keystore.KeyStore
}

func (panicOnGenerate) Generate(ctx context.Context, ref keystore.KeyRef, alg keystore.Algorithm) (crypto.Signer, error) {
	panic("Generate must not be called when bootstrap material already exists")
}
