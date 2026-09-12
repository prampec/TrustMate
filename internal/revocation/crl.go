package revocation

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/prampec/trustmate/internal/pki"
	"github.com/prampec/trustmate/internal/store"
)

// CRLValidity is how long a generated CRL is considered current before
// CRLBuilder regenerates it on next request.
const CRLValidity = 24 * time.Hour

// reasonCodes maps the fixed set of revocation reason strings the api
// package accepts (see internal/api/certificates.go) to RFC 5280 CRLReason
// codes -- crypto/x509 doesn't export these as constants, but
// golang.org/x/crypto/ocsp does (the same RFC 5280 reason values apply to
// both OCSP and CRL entries) and is already a dependency. Anything not in
// this table (there should be nothing, since the api package validates
// first) falls back to Unspecified.
var reasonCodes = map[string]int{
	"unspecified":          ocsp.Unspecified,
	"keyCompromise":        ocsp.KeyCompromise,
	"affiliationChanged":   ocsp.AffiliationChanged,
	"superseded":           ocsp.Superseded,
	"cessationOfOperation": ocsp.CessationOfOperation,
}

// CRLBuilder produces a signed, RFC 5280 CRL for one CA (root or
// intermediate), lazily regenerated and cached in memory -- no background
// scheduler, per docs/design.md's Phase 1 scope. A CRL must only list
// certificates issued by its own signer, so one CRLBuilder instance per
// CA is required -- see CRL's issuer-serial filter below.
type CRLBuilder struct {
	issuer pki.Issuer
	certs  store.CertificateRepository

	mu      sync.Mutex
	cached  []byte
	expires time.Time
}

// NewCRLBuilder returns a CRLBuilder that signs with issuer (that CA's
// certificate and signing key) and lists, from certs, only the revoked
// certificates issuer itself issued.
func NewCRLBuilder(issuer pki.Issuer, certs store.CertificateRepository) *CRLBuilder {
	return &CRLBuilder{issuer: issuer, certs: certs}
}

// Invalidate drops the cached CRL so the next CRL() call regenerates it
// immediately, instead of waiting out CRLValidity. Called after a
// successful revoke so the CRL reflects it right away.
func (b *CRLBuilder) Invalidate() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cached = nil
}

// CRL returns the current DER-encoded CRL, regenerating it if the cached
// copy is absent or stale.
func (b *CRLBuilder) CRL(ctx context.Context) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	if b.cached != nil && now.Before(b.expires) {
		return b.cached, nil
	}

	revoked, err := b.certs.FindRevoked(ctx)
	if err != nil {
		return nil, fmt.Errorf("revocation: listing revoked certificates: %w", err)
	}
	issuerSerial := b.issuer.Cert.SerialNumber.String()
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, rec := range revoked {
		if rec.IssuerSerial != issuerSerial {
			continue
		}
		serial, ok := new(big.Int).SetString(rec.Serial, 10)
		if !ok {
			return nil, fmt.Errorf("revocation: parsing serial %q", rec.Serial)
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: *rec.RevokedAt,
			ReasonCode:     reasonCodes[rec.RevocationReason],
		})
	}

	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(now.Unix()),
		ThisUpdate:                now,
		NextUpdate:                now.Add(CRLValidity),
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, b.issuer.Cert, b.issuer.Signer)
	if err != nil {
		return nil, fmt.Errorf("revocation: creating CRL: %w", err)
	}

	b.cached = der
	b.expires = tmpl.NextUpdate
	return der, nil
}
