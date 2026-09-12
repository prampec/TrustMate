package revocation

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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

// OCSPResponder answers RFC 6960 OCSP requests: "good" for a known,
// unrevoked serial, "revoked" once POST /v1/certificates/{serial}/revoke
// has run, "unknown" for a serial its matched issuer never issued. A
// single /v1/ocsp endpoint serves requests about every CA-issued
// certificate in this deployment (root, intermediate, and every leaf),
// so Respond must sign each response with whichever of issuers actually
// issued the queried certificate -- see matchIssuer. Answering every
// request with one fixed issuer (as a single-issuer responder would)
// produces a response no client can validly verify for a request about
// any other issuer's certificates, the same RFC 5280/6960 issuer
// mismatch bootstrap.go's CRLDP fix addressed for CRLs.
type OCSPResponder struct {
	issuers []pki.Issuer
	certs   store.CertificateRepository
}

// NewOCSPResponder returns an OCSPResponder that looks up serials via
// certs and signs each response with whichever of issuers the request
// identifies (by issuer name/key hash, per RFC 6960) as the certificate's
// issuer. Pass every CA this deployment can be asked about -- currently
// the root and the intermediate.
func NewOCSPResponder(issuers []pki.Issuer, certs store.CertificateRepository) *OCSPResponder {
	return &OCSPResponder{issuers: issuers, certs: certs}
}

// Respond parses a DER-encoded OCSP request and returns a DER-encoded
// OCSP response, signed by the issuer the request identifies. If that
// issuer isn't one this responder is authoritative for, it returns RFC
// 6960's pre-serialized "unauthorized" error response (unsigned, since
// no key of ours could validly speak for an issuer we don't recognize).
func (o *OCSPResponder) Respond(ctx context.Context, rawRequest []byte) ([]byte, error) {
	req, err := ocsp.ParseRequest(rawRequest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedRequest, err)
	}

	issuer, ok := o.matchIssuer(req)
	if !ok {
		return ocsp.UnauthorizedErrorResponse, nil
	}
	issuerSerial := issuer.Cert.SerialNumber.String()

	status := ocsp.Unknown
	var revokedAt time.Time
	if rec, err := o.certs.GetBySerial(ctx, req.SerialNumber.String()); err == nil {
		if rec.IssuerSerial == issuerSerial {
			if rec.RevokedAt != nil {
				status = ocsp.Revoked
				revokedAt = *rec.RevokedAt
			} else {
				status = ocsp.Good
			}
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("revocation: looking up serial %s: %w", req.SerialNumber, err)
	}

	now := time.Now()
	tmpl := ocsp.Response{
		Status:       status,
		SerialNumber: req.SerialNumber,
		ThisUpdate:   now,
		NextUpdate:   now.Add(OCSPValidity),
		RevokedAt:    revokedAt,
	}
	resp, err := ocsp.CreateResponse(issuer.Cert, issuer.Cert, tmpl, issuer.Signer)
	if err != nil {
		return nil, fmt.Errorf("revocation: creating OCSP response: %w", err)
	}
	return resp, nil
}

// matchIssuer finds the configured issuer whose name/key hash (computed
// with req's own hash algorithm) matches req's IssuerNameHash/
// IssuerKeyHash -- the RFC 6960 way a request names which CA it's asking
// about, mirroring how golang.org/x/crypto/ocsp.CreateRequest computes
// those hashes from a caller-supplied issuer cert.
func (o *OCSPResponder) matchIssuer(req *ocsp.Request) (pki.Issuer, bool) {
	for _, issuer := range o.issuers {
		nameHash, keyHash, err := issuerHashes(issuer.Cert, req.HashAlgorithm)
		if err != nil {
			continue
		}
		if bytes.Equal(nameHash, req.IssuerNameHash) && bytes.Equal(keyHash, req.IssuerKeyHash) {
			return issuer, true
		}
	}
	return pki.Issuer{}, false
}

// issuerHashes computes the OCSP issuerNameHash/issuerKeyHash for issuer
// under hashFunc -- the same computation ocsp.CreateRequest performs, so
// a request built against a real issuer certificate matches here.
func issuerHashes(issuer *x509.Certificate, hashFunc crypto.Hash) (nameHash, keyHash []byte, err error) {
	if !hashFunc.Available() {
		return nil, nil, fmt.Errorf("revocation: OCSP request hash algorithm unavailable")
	}

	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return nil, nil, fmt.Errorf("revocation: parsing issuer public key info: %w", err)
	}

	h := hashFunc.New()
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	keyHash = h.Sum(nil)

	h.Reset()
	h.Write(issuer.RawSubject)
	nameHash = h.Sum(nil)
	return nameHash, keyHash, nil
}
