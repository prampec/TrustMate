package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/prampec/trustmate/internal/bootstrap"
	"github.com/prampec/trustmate/internal/config"
	"github.com/prampec/trustmate/internal/keystore"
	"github.com/prampec/trustmate/internal/observability"
	"github.com/prampec/trustmate/internal/pki"
	"github.com/prampec/trustmate/internal/profiles"
	"github.com/prampec/trustmate/internal/revocation"
	"github.com/prampec/trustmate/internal/store"
	"github.com/prampec/trustmate/internal/store/sqlite"
	"github.com/prampec/trustmate/internal/tsa"
)

// newTestDeps bootstraps a full CA (root/intermediate/admin/server-tls)
// against a temp SQLite store and file keystore, then builds a Deps with
// a real IntermediateIssuer/CRLBuilder/OCSPResponder/TSAResponder -- the
// same fixtures bootstrap_test.go uses, since only real, chain-verifiable
// material exercises these handlers meaningfully.
func newTestDeps(t *testing.T, mods ModuleConfig) Deps {
	t.Helper()

	st, err := sqlite.Open(filepath.Join(t.TempDir(), "trustmate.db"))
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	ks, err := keystore.NewFileKeyStore(filepath.Join(t.TempDir(), "keys"), []byte("test-passphrase"))
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}

	cfg := config.Defaults()
	cfg.Bootstrap.OutputDir = filepath.Join(t.TempDir(), "bootstrap")
	cfg.Modules.Revocation = mods.EnableRevocation
	cfg.Modules.TSA = mods.EnableTSA

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := bootstrap.Run(context.Background(), logger, cfg, st, ks); err != nil {
		t.Fatalf("bootstrap.Run: %v", err)
	}

	issuer, err := bootstrap.LoadIntermediateIssuer(context.Background(), st, ks)
	if err != nil {
		t.Fatalf("LoadIntermediateIssuer: %v", err)
	}

	var tsaResponder *tsa.Responder
	if mods.EnableTSA {
		tsaIssuer, err := bootstrap.LoadTSAIssuer(context.Background(), st, ks)
		if err != nil {
			t.Fatalf("LoadTSAIssuer: %v", err)
		}
		tsaResponder = tsa.NewResponder(tsaIssuer, issuer.Cert)
	}

	registry, err := profiles.NewRegistry(context.Background(), st.Profiles(), "")
	if err != nil {
		t.Fatalf("profiles.NewRegistry: %v", err)
	}

	return Deps{
		Logger:             logger,
		Store:              st,
		IntermediateIssuer: issuer,
		PublicBaseURL:      cfg.Server.PublicBaseURL,
		KeyStore:           ks,
		TSACommonName:      cfg.Bootstrap.TSACommonName,
		TSAValidity:        cfg.Bootstrap.TSAValidity,
		ModuleConfig:       mods,
		Profiles:           registry,
		Metrics:            observability.NewMetrics(),
		CRLBuilder:         revocation.NewCRLBuilder(issuer, st.Certificates()),
		OCSPResponder:      revocation.NewOCSPResponder(issuer, st.Certificates()),
		TSAResponder:       tsaResponder,
	}
}

// adminCert returns the bootstrap-issued admin certificate, which
// newTestDeps' bootstrap.Run call already assigned the admin role to --
// see internal/bootstrap/bootstrap.go. Tests attach it to a request via
// withClientCert to exercise routes gated by requireRole.
//
// Looks it up via client_roles (role == admin), not "the latest
// certificate issued against the default/client-auth profile": role is
// deliberately independent of profile (a dedicated role-assignment
// table, not derived from profile name -- see docs/design.md's Phase 3
// entry), and issueClientCert below issues manager-role test certs
// against that same default profile too, so "latest default-profile
// cert" is not reliably the admin one once a test has issued others.
func adminCert(t *testing.T, deps Deps) *x509.Certificate {
	t.Helper()
	roles, err := deps.Store.ClientRoles().List(context.Background())
	if err != nil {
		t.Fatalf("ClientRoles().List: %v", err)
	}
	var adminSerial string
	for _, r := range roles {
		if r.Role == store.RoleAdmin {
			adminSerial = r.CertSerial
			break
		}
	}
	if adminSerial == "" {
		t.Fatal("adminCert: no certificate with the admin role found")
	}
	rec, err := deps.Store.Certificates().GetBySerial(context.Background(), adminSerial)
	if err != nil {
		t.Fatalf("GetBySerial(admin serial): %v", err)
	}
	block, _ := pem.Decode(rec.PEM)
	if block == nil {
		t.Fatal("adminCert: admin certificate PEM does not decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("adminCert: parsing certificate: %v", err)
	}
	return cert
}

// withClientCert simulates the mTLS peer certificate crypto/tls would
// have set on r.TLS after a real handshake -- httptest.NewRequest never
// performs one, so requireRole (internal/api/auth.go) has nothing to read
// unless a test sets this itself.
func withClientCert(r *http.Request, cert *x509.Certificate) *http.Request {
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return r
}

// issueClientCert issues a fresh client-auth leaf certificate against
// deps.IntermediateIssuer and, unless role is empty, assigns it role in
// client_roles -- letting auth tests exercise a cert with no role, a
// manager-only cert, and an admin cert without reusing the single
// bootstrap admin identity for every case.
func issueClientCert(t *testing.T, deps Deps, cn string, role store.ClientRole) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	profile := profiles.Default().WithIssuerURLs(deps.PublicBaseURL, deps.ModuleConfig.EnableRevocation)
	now := time.Now()
	cert, err := pki.IssueLeaf(profile, pkix.Name{CommonName: cn}, key.Public(),
		deps.IntermediateIssuer, now, now.Add(profile.Validity), nil)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	if err := deps.Store.Certificates().Create(context.Background(), store.CertificateRecord{
		Serial:       cert.SerialNumber.String(),
		Kind:         store.CertKindLeaf,
		ProfileName:  profile.Name,
		Subject:      cert.Subject.String(),
		IssuerSerial: deps.IntermediateIssuer.Cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		PEM:          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		CreatedAt:    now.UTC(),
	}); err != nil {
		t.Fatalf("Certificates().Create: %v", err)
	}
	if role != "" {
		if err := deps.Store.ClientRoles().Assign(context.Background(), store.ClientRoleRecord{
			CertSerial: cert.SerialNumber.String(), Role: role, CreatedAt: now.UTC(),
		}); err != nil {
			t.Fatalf("ClientRoles().Assign: %v", err)
		}
	}
	return cert
}

// getAs issues an authenticated GET, or an anonymous one if cert is nil.
func getAs(t *testing.T, router http.Handler, path string, cert *x509.Certificate) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cert != nil {
		withClientCert(req, cert)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}
