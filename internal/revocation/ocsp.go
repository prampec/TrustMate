package revocation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/prampec/trustmate/internal/pki"
	"github.com/prampec/trustmate/internal/store"
)

// OCSPValidity is how long an issued OCSP response is valid for.
const OCSPValidity = 1 * time.Hour

// ErrMalformedRequest is returned by Respond when rawRequest itself
// could not be parsed as a DER-encoded OCSP request -- as opposed to a
// well-formed request that failed for an internal reason (e.g. a
// datastore error), which callers should treat as a server error, not a
// bad request.
var ErrMalformedRequest = errors.New("revocation: malformed OCSP request")

// OCSPResponder answers RFC 6960 OCSP requests. No revoke endpoint
// exists yet in this phase (see docs/design.md's Phase 1 scope), so it
// only distinguishes a known serial ("good") from an unknown one --
// never "revoked". The responder cert is the intermediate itself; there
// is no delegated OCSP-signing identity in Phase 1.
type OCSPResponder struct {
	issuer pki.Issuer
	certs  store.CertificateRepository
}

// NewOCSPResponder returns an OCSPResponder that signs with issuer (the
// intermediate CA) and looks up serials via certs.
func NewOCSPResponder(issuer pki.Issuer, certs store.CertificateRepository) *OCSPResponder {
	return &OCSPResponder{issuer: issuer, certs: certs}
}

// Respond parses a DER-encoded OCSP request and returns a signed,
// DER-encoded OCSP response.
func (o *OCSPResponder) Respond(ctx context.Context, rawRequest []byte) ([]byte, error) {
	req, err := ocsp.ParseRequest(rawRequest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedRequest, err)
	}

	status := ocsp.Unknown
	if _, err := o.certs.GetBySerial(ctx, req.SerialNumber.String()); err == nil {
		status = ocsp.Good
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("revocation: looking up serial %s: %w", req.SerialNumber, err)
	}

	now := time.Now()
	tmpl := ocsp.Response{
		Status:       status,
		SerialNumber: req.SerialNumber,
		ThisUpdate:   now,
		NextUpdate:   now.Add(OCSPValidity),
	}
	resp, err := ocsp.CreateResponse(o.issuer.Cert, o.issuer.Cert, tmpl, o.issuer.Signer)
	if err != nil {
		return nil, fmt.Errorf("revocation: creating OCSP response: %w", err)
	}
	return resp, nil
}
