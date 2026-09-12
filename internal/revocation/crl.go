package revocation

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/prampec/trustmate/internal/pki"
)

// CRLValidity is how long a generated CRL is considered current before
// CRLBuilder regenerates it on next request.
const CRLValidity = 24 * time.Hour

// CRLBuilder produces a signed, RFC 5280 CRL for the intermediate CA,
// lazily regenerated and cached in memory -- no background scheduler, per
// docs/design.md's Phase 1 scope. Nothing is revocable yet (no revoke
// endpoint exists in this phase), so RevokedCertificateEntries is always
// empty; the CRL is nonetheless real and correctly signed.
type CRLBuilder struct {
	issuer pki.Issuer

	mu      sync.Mutex
	cached  []byte
	expires time.Time
}

// NewCRLBuilder returns a CRLBuilder that signs with issuer (the
// intermediate CA's certificate and signing key).
func NewCRLBuilder(issuer pki.Issuer) *CRLBuilder {
	return &CRLBuilder{issuer: issuer}
}

// CRL returns the current DER-encoded CRL, regenerating it if the cached
// copy is absent or stale.
func (b *CRLBuilder) CRL(_ context.Context) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	if b.cached != nil && now.Before(b.expires) {
		return b.cached, nil
	}

	tmpl := &x509.RevocationList{
		Number:     big.NewInt(now.Unix()),
		ThisUpdate: now,
		NextUpdate: now.Add(CRLValidity),
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, b.issuer.Cert, b.issuer.Signer)
	if err != nil {
		return nil, fmt.Errorf("revocation: creating CRL: %w", err)
	}

	b.cached = der
	b.expires = tmpl.NextUpdate
	return der, nil
}
