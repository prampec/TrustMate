package tsa

import (
	"context"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/prampec/trustmate/internal/keystore"
	"github.com/prampec/trustmate/internal/pki"
	"github.com/prampec/trustmate/internal/profiles"
	"github.com/prampec/trustmate/internal/store"
)

// IdentityParams carries the profile-independent parameters needed to
// mint a TSA signing identity -- shared by internal/bootstrap's first-run
// generation and the runtime rotation endpoint so both mint identities
// the same way.
type IdentityParams struct {
	CommonName        string
	Validity          time.Duration
	PublicBaseURL     string
	RevocationEnabled bool
}

// IssueIdentity generates a new TSA signing keypair under ref and issues
// its certificate against the built-in tsa profile, signed by inter, then
// persists the certificate record. The caller picks ref: bootstrap uses a
// fixed, well-known ref for the first-ever TSA identity; rotation mints a
// fresh one each time (see keystore.FreshRef), since KeyStore.Generate
// refuses to overwrite an existing ref.
func IssueIdentity(ctx context.Context, ref keystore.KeyRef, params IdentityParams, st store.Store, ks keystore.KeyStore, inter pki.Issuer) (pki.Issuer, store.CertificateRecord, error) {
	signer, err := ks.Generate(ctx, ref, keystore.AlgorithmECDSAP256)
	if err != nil {
		return pki.Issuer{}, store.CertificateRecord{}, fmt.Errorf("tsa: generating key: %w", err)
	}

	profile := profiles.TSA().WithIssuerURLs(params.PublicBaseURL, params.RevocationEnabled)
	now := time.Now()
	cert, err := pki.IssueLeaf(profile, pkix.Name{CommonName: params.CommonName}, signer.Public(),
		inter, now, now.Add(params.Validity), nil)
	if err != nil {
		return pki.Issuer{}, store.CertificateRecord{}, fmt.Errorf("tsa: issuing certificate: %w", err)
	}

	rec := store.CertificateRecord{
		Serial:       cert.SerialNumber.String(),
		Kind:         store.CertKindLeaf,
		ProfileName:  profile.Name,
		Subject:      cert.Subject.String(),
		IssuerSerial: inter.Cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		PEM:          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		KeyRef:       string(ref),
		CreatedAt:    now.UTC(),
	}
	if err := st.Certificates().Create(ctx, rec); err != nil {
		return pki.Issuer{}, store.CertificateRecord{}, fmt.Errorf("tsa: persisting certificate: %w", err)
	}

	return pki.Issuer{Cert: cert, Signer: signer}, rec, nil
}
