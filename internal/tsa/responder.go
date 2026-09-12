package tsa

import (
	"context"
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/digitorus/timestamp"

	"github.com/prampec/trustmate/internal/pki"
)

// ErrMalformedRequest is returned by Respond when rawRequest itself could
// not be parsed as a DER-encoded RFC 3161 TimeStampReq -- as opposed to a
// well-formed request that failed for an internal reason (which callers
// should treat as a server error). Mirrors revocation.ErrMalformedRequest.
var ErrMalformedRequest = errors.New("tsa: malformed timestamp request")

// ErrUnsupportedRequest is returned by Respond for a well-formed request
// this responder cannot service -- currently only a SHA-1 message
// imprint, which github.com/digitorus/timestamp cannot embed in the
// mandatory ESSCertIDv2 signed attribute (RFC 5035 requires a stronger
// hash there). SHA-1 is deprecated for timestamping regardless (RFC
// 3161's own erratum discussion, and most relying parties reject it), so
// this is not treated as a gap worth working around.
var ErrUnsupportedRequest = errors.New("tsa: unsupported timestamp request")

// PolicyOID identifies TrustMate's timestamping policy in issued tokens'
// TSTInfo.policy field, which RFC 3161 section 2.4.2 requires to be
// present. TrustMate has no IANA-registered private enterprise number, so
// this is a private/placeholder OID (the same class of placeholder
// freetsa.org's public test TSA uses) -- replace it with a registered
// policy OID before any production PKI use.
var PolicyOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55698, 1, 1}

// Responder answers RFC 3161 Time-Stamp requests, signing tokens with its
// own bootstrap-issued identity (see internal/bootstrap's
// generateTSALeaf/LoadTSAIssuer) -- never the intermediate CA directly,
// unlike Phase 1's OCSP responder.
type Responder struct {
	issuer       pki.Issuer
	intermediate *x509.Certificate

	mu          sync.Mutex
	lastGenTime time.Time
}

// NewResponder returns a Responder that signs with issuer (the TSA's own
// certificate/key) and includes intermediate in the response's
// certificate chain when a request asks for one.
func NewResponder(issuer pki.Issuer, intermediate *x509.Certificate) *Responder {
	return &Responder{issuer: issuer, intermediate: intermediate}
}

// Respond parses a DER-encoded RFC 3161 TimeStampReq and returns a
// signed, DER-encoded TimeStampResp.
func (r *Responder) Respond(ctx context.Context, rawRequest []byte) ([]byte, error) {
	req, err := timestamp.ParseRequest(rawRequest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedRequest, err)
	}
	if req.HashAlgorithm == crypto.SHA1 {
		return nil, fmt.Errorf("%w: SHA-1 message imprints are not supported", ErrUnsupportedRequest)
	}

	ts := timestamp.Timestamp{
		HashAlgorithm:     req.HashAlgorithm,
		HashedMessage:     req.HashedMessage,
		Time:              r.nextGenTime(),
		Policy:            PolicyOID,
		Nonce:             req.Nonce,
		AddTSACertificate: req.Certificates,
	}
	if req.Certificates && r.intermediate != nil {
		ts.Certificates = []*x509.Certificate{r.intermediate}
	}

	resp, err := ts.CreateResponseWithOpts(r.issuer.Cert, r.issuer.Signer, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("tsa: creating response: %w", err)
	}
	return resp, nil
}

// nextGenTime returns the current time, bumped forward by at least one
// second over the previous call's result if necessary, so successive
// tokens have strictly increasing TSTInfo.genTime -- per docs/design.md's
// security section ("enforce monotonic-ish timestamps to make ...
// backdating detectable"). Truncated to the second because
// github.com/digitorus/timestamp marshals TSTInfo.Time as ASN.1
// GeneralizedTime with no sub-second precision (`asn1:"generalized"`) --
// a sub-second bump would be silently discarded by that encoding and
// defeat the monotonicity guarantee on the wire. This guard is in-memory
// and reset on restart, which is acceptable for v1's single-instance
// scope (see docs/design.md's Phase 4/5 horizontal-scaling roadmap).
func (r *Responder) nextGenTime() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC().Truncate(time.Second)
	if !now.After(r.lastGenTime) {
		now = r.lastGenTime.Add(time.Second)
	}
	r.lastGenTime = now
	return now
}
