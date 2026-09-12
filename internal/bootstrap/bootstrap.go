// Package bootstrap drives TrustMate's first-run setup: generating the
// root CA, intermediate CA, admin REST access certificate, and the
// server's own TLS certificate, and persisting the default certificate
// profile. See docs/design.md's Phase 0 roadmap entry.
package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/prampec/trustmate/internal/config"
	"github.com/prampec/trustmate/internal/keystore"
	"github.com/prampec/trustmate/internal/pki"
	"github.com/prampec/trustmate/internal/profiles"
	"github.com/prampec/trustmate/internal/store"
)

const (
	refRoot      keystore.KeyRef = "root"
	refServerTLS keystore.KeyRef = "server-tls"

	// IntermediateKeyRef is the keystore ref for the intermediate CA's
	// signing key, exported so callers outside this package (e.g.
	// LoadIntermediateIssuer) can reload it at runtime.
	IntermediateKeyRef keystore.KeyRef = "intermediate"

	bootstrapAlgorithm = keystore.AlgorithmECDSAP256
)

// Result reports what Run did.
type Result struct {
	AlreadyBootstrapped bool
}

// Run generates and persists the root CA, intermediate CA, admin access
// certificate, and server TLS certificate on first run. On subsequent
// runs it detects existing CA material (a root certificate already in
// the store) and returns immediately without touching the keystore.
func Run(ctx context.Context, logger *slog.Logger, cfg config.Config, st store.Store, ks keystore.KeyStore) (Result, error) {
	roots, err := st.Certificates().FindByKind(ctx, store.CertKindRoot)
	if err != nil {
		return Result{}, fmt.Errorf("bootstrap: checking for existing root CA: %w", err)
	}
	if len(roots) > 0 {
		logger.Info("bootstrap: CA material already present, skipping")
		return Result{AlreadyBootstrapped: true}, nil
	}

	logger.Info("bootstrap: no CA material found, generating root, intermediate, admin, and server-tls certificates")

	if err := persistDefaultProfiles(ctx, st); err != nil {
		return Result{}, err
	}

	root, err := generateRoot(ctx, cfg, st, ks)
	if err != nil {
		return Result{}, err
	}
	logger.Info("bootstrap: root CA generated", "serial", root.Cert.SerialNumber.String())

	inter, err := generateIntermediate(ctx, cfg, st, ks, root)
	if err != nil {
		return Result{}, err
	}
	logger.Info("bootstrap: intermediate CA generated", "serial", inter.Cert.SerialNumber.String())

	adminCert, adminKey, err := generateAdminLeaf(ctx, cfg, st, inter)
	if err != nil {
		return Result{}, err
	}
	logger.Info("bootstrap: admin access certificate generated", "serial", adminCert.SerialNumber.String())

	serverCert, err := generateServerTLSLeaf(ctx, cfg, st, ks, inter)
	if err != nil {
		return Result{}, err
	}
	logger.Info("bootstrap: server TLS certificate generated", "serial", serverCert.Cert.SerialNumber.String())

	if err := writeBootstrapOutput(cfg.Bootstrap.OutputDir, root.Cert, inter.Cert, adminCert, adminKey); err != nil {
		return Result{}, err
	}
	logger.Warn("bootstrap: admin-key.pem written to bootstrap output dir is an unencrypted one-time export -- retrieve it and move it off this host",
		"dir", cfg.Bootstrap.OutputDir)

	for _, e := range []store.AuditEntry{
		{Timestamp: time.Now().UTC(), Actor: "bootstrap", Action: "issue", Target: root.Cert.SerialNumber.String(), Detail: "root CA"},
		{Timestamp: time.Now().UTC(), Actor: "bootstrap", Action: "issue", Target: inter.Cert.SerialNumber.String(), Detail: "intermediate CA"},
		{Timestamp: time.Now().UTC(), Actor: "bootstrap", Action: "issue", Target: adminCert.SerialNumber.String(), Detail: "admin access certificate"},
		{Timestamp: time.Now().UTC(), Actor: "bootstrap", Action: "issue", Target: serverCert.Cert.SerialNumber.String(), Detail: "server TLS certificate"},
	} {
		if err := st.Audit().Append(ctx, e); err != nil {
			return Result{}, fmt.Errorf("bootstrap: writing audit entry: %w", err)
		}
	}

	return Result{AlreadyBootstrapped: false}, nil
}

func persistDefaultProfiles(ctx context.Context, st store.Store) error {
	for _, p := range []profiles.Profile{profiles.Default(), profiles.ServerTLS()} {
		data, err := json.Marshal(p)
		if err != nil {
			return fmt.Errorf("bootstrap: encoding profile %s: %w", p.Name, err)
		}
		if err := st.Profiles().Upsert(ctx, store.ProfileRecord{
			Name:      p.Name,
			Version:   p.Version,
			Data:      data,
			CreatedAt: time.Now().UTC(),
		}); err != nil {
			return fmt.Errorf("bootstrap: persisting profile %s: %w", p.Name, err)
		}
	}
	return nil
}

func generateRoot(ctx context.Context, cfg config.Config, st store.Store, ks keystore.KeyStore) (pki.Issuer, error) {
	signer, err := ks.Generate(ctx, refRoot, bootstrapAlgorithm)
	if err != nil {
		return pki.Issuer{}, fmt.Errorf("bootstrap: generating root key: %w", err)
	}

	now := time.Now()
	cert, err := pki.SelfSignedCA(pki.CertRequest{
		Subject:   pkix.Name{CommonName: cfg.Bootstrap.RootCommonName},
		NotBefore: now,
		NotAfter:  now.Add(cfg.Bootstrap.RootValidity),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, signer)
	if err != nil {
		return pki.Issuer{}, fmt.Errorf("bootstrap: issuing root CA: %w", err)
	}

	if err := createCertRecord(ctx, st, cert, store.CertKindRoot, "", "", string(refRoot)); err != nil {
		return pki.Issuer{}, err
	}
	return pki.Issuer{Cert: cert, Signer: signer}, nil
}

func generateIntermediate(ctx context.Context, cfg config.Config, st store.Store, ks keystore.KeyStore, root pki.Issuer) (pki.Issuer, error) {
	signer, err := ks.Generate(ctx, IntermediateKeyRef, bootstrapAlgorithm)
	if err != nil {
		return pki.Issuer{}, fmt.Errorf("bootstrap: generating intermediate key: %w", err)
	}

	req := pki.CertRequest{
		Subject:      pkix.Name{CommonName: cfg.Bootstrap.IntermediateCommonName},
		PublicKey:    signer.Public(),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(cfg.Bootstrap.IntermediateValidity),
		IsCA:         true,
		PathLenZero:  true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		AIAIssuerURL: cfg.Server.PublicBaseURL + "/v1/ca/root.pem",
	}
	// Resolves design.md's "revocation list info is already available in
	// the intermediate certificate if module is enabled" verification.
	if cfg.Modules.Revocation {
		req.CRLURL = cfg.Server.PublicBaseURL + "/v1/crl/intermediate.crl"
		req.OCSPURL = cfg.Server.PublicBaseURL + "/v1/ocsp"
	}

	cert, err := pki.IssueCA(req, root)
	if err != nil {
		return pki.Issuer{}, fmt.Errorf("bootstrap: issuing intermediate CA: %w", err)
	}

	if err := createCertRecord(ctx, st, cert, store.CertKindIntermediate, "", root.Cert.SerialNumber.String(), string(IntermediateKeyRef)); err != nil {
		return pki.Issuer{}, err
	}
	return pki.Issuer{Cert: cert, Signer: signer}, nil
}

// generateAdminLeaf generates the admin keypair in memory only -- it is
// never handed to the keystore, and is discarded by the caller once
// written to the bootstrap output dir. See the Phase 0 plan's decision
// that the server keeps no server-side custody of this key.
func generateAdminLeaf(ctx context.Context, cfg config.Config, st store.Store, inter pki.Issuer) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("bootstrap: generating admin key: %w", err)
	}

	profile := profiles.Default().WithIssuerURLs(cfg.Server.PublicBaseURL, cfg.Modules.Revocation)
	now := time.Now()
	cert, err := pki.IssueLeaf(profile, pkix.Name{CommonName: cfg.Bootstrap.AdminCommonName}, key.Public(),
		inter, now, now.Add(cfg.Bootstrap.AdminValidity), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("bootstrap: issuing admin certificate: %w", err)
	}

	if err := createCertRecord(ctx, st, cert, store.CertKindLeaf, profile.Name, inter.Cert.SerialNumber.String(), ""); err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func generateServerTLSLeaf(ctx context.Context, cfg config.Config, st store.Store, ks keystore.KeyStore, inter pki.Issuer) (pki.Issuer, error) {
	signer, err := ks.Generate(ctx, refServerTLS, bootstrapAlgorithm)
	if err != nil {
		return pki.Issuer{}, fmt.Errorf("bootstrap: generating server-tls key: %w", err)
	}

	profile := profiles.ServerTLS().WithIssuerURLs(cfg.Server.PublicBaseURL, cfg.Modules.Revocation)
	now := time.Now()
	cert, err := pki.IssueLeaf(profile, pkix.Name{CommonName: cfg.Bootstrap.ServerCommonName}, signer.Public(),
		inter, now, now.Add(cfg.Bootstrap.ServerValidity), cfg.Server.TLSSANs)
	if err != nil {
		return pki.Issuer{}, fmt.Errorf("bootstrap: issuing server-tls certificate: %w", err)
	}

	if err := createCertRecord(ctx, st, cert, store.CertKindLeaf, profile.Name, inter.Cert.SerialNumber.String(), string(refServerTLS)); err != nil {
		return pki.Issuer{}, err
	}
	return pki.Issuer{Cert: cert, Signer: signer}, nil
}

func createCertRecord(ctx context.Context, st store.Store, cert *x509.Certificate, kind store.CertKind, profileName, issuerSerial, keyRef string) error {
	return st.Certificates().Create(ctx, store.CertificateRecord{
		Serial:       cert.SerialNumber.String(),
		Kind:         kind,
		ProfileName:  profileName,
		Subject:      cert.Subject.String(),
		IssuerSerial: issuerSerial,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		PEM:          encodePEM(cert.Raw),
		KeyRef:       keyRef,
		CreatedAt:    time.Now().UTC(),
	})
}

func encodePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeBootstrapOutput(dir string, root, inter, admin *x509.Certificate, adminKey *ecdsa.PrivateKey) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("bootstrap: creating output dir %s: %w", dir, err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(adminKey)
	if err != nil {
		return fmt.Errorf("bootstrap: marshalling admin key: %w", err)
	}

	files := map[string][]byte{
		"root.pem":         encodePEM(root.Raw),
		"intermediate.pem": encodePEM(inter.Raw),
		"chain.pem":        append(encodePEM(inter.Raw), encodePEM(root.Raw)...),
		"admin.pem":        encodePEM(admin.Raw),
		"admin-key.pem":    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
	for name, data := range files {
		perm := os.FileMode(0o644)
		if name == "admin-key.pem" {
			perm = 0o600
		}
		path := filepath.Join(dir, name)
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, data, perm); err != nil {
			return fmt.Errorf("bootstrap: writing %s: %w", tmp, err)
		}
		if err := os.Rename(tmp, path); err != nil {
			return fmt.Errorf("bootstrap: renaming %s to %s: %w", tmp, path, err)
		}
	}
	return nil
}
