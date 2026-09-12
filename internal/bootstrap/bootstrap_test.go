package bootstrap

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
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

func TestRunGeneratesFiveCertificatesAndBootstrapOutput(t *testing.T) {
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
	if err != nil || len(leaves) != 3 {
		t.Fatalf("FindByKind(leaf) = %v, %v; want 3 rows (admin + server-tls + tsa)", leaves, err)
	}

	for _, name := range []string{"root.pem", "intermediate.pem", "chain.pem", "admin.pem", "admin-key.pem", "tsa.pem"} {
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

func TestRunAssignsAdminRoleToBootstrapAdminCert(t *testing.T) {
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Bootstrap.OutputDir = filepath.Join(t.TempDir(), "bootstrap")
	st := newTestStore(t)
	ks := newTestKeyStore(t)

	if _, err := Run(ctx, discardLogger(), cfg, st, ks); err != nil {
		t.Fatalf("Run: %v", err)
	}

	adminRec, err := st.Certificates().GetLatestByProfile(ctx, "default")
	if err != nil {
		t.Fatalf("GetLatestByProfile(default): %v", err)
	}

	roleRec, err := st.ClientRoles().Get(ctx, adminRec.Serial)
	if err != nil {
		t.Fatalf("ClientRoles().Get(admin serial): %v", err)
	}
	if roleRec.Role != store.RoleAdmin {
		t.Errorf("bootstrap admin cert role = %q, want admin", roleRec.Role)
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
	if err != nil || len(leaves) != 3 {
		t.Fatalf("FindByKind(leaf) after second Run = %v, %v; want still 3 rows", leaves, err)
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
	if err != nil || len(leaves) != 3 {
		t.Fatalf("FindByKind(leaf) = %v, %v; want 3 rows", leaves, err)
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

func TestRunGeneratesTSAIdentityWithCriticalTimeStampingEKU(t *testing.T) {
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Bootstrap.OutputDir = filepath.Join(t.TempDir(), "bootstrap")
	st := newTestStore(t)
	ks := newTestKeyStore(t)

	if _, err := Run(ctx, discardLogger(), cfg, st, ks); err != nil {
		t.Fatalf("Run: %v", err)
	}

	rec, err := st.Certificates().GetLatestByProfile(ctx, "tsa")
	if err != nil {
		t.Fatalf("GetLatestByProfile(tsa): %v", err)
	}
	if rec.KeyRef != "tsa" {
		t.Errorf("KeyRef = %q, want %q", rec.KeyRef, "tsa")
	}
	cert := parseCertPEM(t, rec.PEM)

	inters, err := st.Certificates().FindByKind(ctx, store.CertKindIntermediate)
	if err != nil || len(inters) != 1 {
		t.Fatalf("FindByKind(intermediate) = %v, %v; want 1 row", inters, err)
	}
	interCert := parseCertPEM(t, inters[0].PEM)
	if err := cert.CheckSignatureFrom(interCert); err != nil {
		t.Errorf("TSA cert does not chain to intermediate: %v", err)
	}

	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping {
		t.Errorf("ExtKeyUsage = %v, want exactly {ExtKeyUsageTimeStamping}", cert.ExtKeyUsage)
	}
	var criticalFound bool
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(asn1ExtKeyUsageOID) {
			criticalFound = ext.Critical
		}
	}
	if !criticalFound {
		t.Error("EKU extension missing or not marked critical")
	}

	issuer, err := LoadTSAIssuer(ctx, st, ks)
	if err != nil {
		t.Fatalf("LoadTSAIssuer: %v", err)
	}
	if issuer.Cert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("LoadTSAIssuer serial = %v, want %v", issuer.Cert.SerialNumber, cert.SerialNumber)
	}
}

func TestRunSkipsTSAIdentityWhenModuleDisabled(t *testing.T) {
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Bootstrap.OutputDir = filepath.Join(t.TempDir(), "bootstrap")
	cfg.Modules.TSA = false
	st := newTestStore(t)
	ks := newTestKeyStore(t)

	if _, err := Run(ctx, discardLogger(), cfg, st, ks); err != nil {
		t.Fatalf("Run: %v", err)
	}

	leaves, err := st.Certificates().FindByKind(ctx, store.CertKindLeaf)
	if err != nil || len(leaves) != 2 {
		t.Fatalf("FindByKind(leaf) = %v, %v; want 2 rows (admin + server-tls, no tsa)", leaves, err)
	}
	if _, err := os.Stat(filepath.Join(cfg.Bootstrap.OutputDir, "tsa.pem")); err == nil {
		t.Error("tsa.pem was written to bootstrap output dir, want it absent when the TSA module is disabled")
	}

	if _, err := LoadTSAIssuer(ctx, st, ks); err == nil {
		t.Error("LoadTSAIssuer succeeded with no TSA identity ever generated, want an error")
	}
}

// asn1ExtKeyUsageOID is the Extended Key Usage extension's OID (RFC 5280
// section 4.2.1.12), duplicated here rather than exported from pki to
// keep this assertion black-box.
var asn1ExtKeyUsageOID = asn1.ObjectIdentifier{2, 5, 29, 37}

// panicOnGenerate wraps a KeyStore and panics if Generate is ever
// called, proving the idempotency short-circuit never touches the
// keystore on a restart.
type panicOnGenerate struct {
	keystore.KeyStore
}

func (panicOnGenerate) Generate(ctx context.Context, ref keystore.KeyRef, alg keystore.Algorithm) (crypto.Signer, error) {
	panic("Generate must not be called when bootstrap material already exists")
}
