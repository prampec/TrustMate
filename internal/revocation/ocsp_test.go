package revocation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/prampec/trustmate/internal/pki"
	"github.com/prampec/trustmate/internal/profiles"
	"github.com/prampec/trustmate/internal/store"
	"github.com/prampec/trustmate/internal/store/sqlite"
)

func testLeaf(t *testing.T, issuer pki.Issuer, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert, err := pki.IssueLeaf(profiles.DocumentSigning(), pkix.Name{CommonName: cn}, key.Public(),
		issuer, now, now.Add(time.Hour), nil)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	return cert
}

func TestOCSPResponderGoodAndUnknown(t *testing.T) {
	issuer := testIssuer(t)

	st, err := sqlite.Open(filepath.Join(t.TempDir(), "trustmate.db"))
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	if err := st.Certificates().Create(context.Background(), store.CertificateRecord{
		Serial:    issuer.Cert.SerialNumber.String(),
		Kind:      store.CertKindIntermediate,
		Subject:   issuer.Cert.Subject.String(),
		NotBefore: issuer.Cert.NotBefore,
		NotAfter:  issuer.Cert.NotAfter,
		PEM:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Cert.Raw}),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Certificates().Create(intermediate): %v", err)
	}

	knownLeaf := testLeaf(t, issuer, "known-leaf")
	if err := st.Certificates().Create(context.Background(), store.CertificateRecord{
		Serial:       knownLeaf.SerialNumber.String(),
		Kind:         store.CertKindLeaf,
		Subject:      knownLeaf.Subject.String(),
		IssuerSerial: issuer.Cert.SerialNumber.String(),
		NotBefore:    knownLeaf.NotBefore,
		NotAfter:     knownLeaf.NotAfter,
		PEM:          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: knownLeaf.Raw}),
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Certificates().Create(leaf): %v", err)
	}

	unknownLeaf := testLeaf(t, issuer, "unknown-leaf")

	responder := NewOCSPResponder([]pki.Issuer{issuer}, st.Certificates())

	knownReq, err := ocsp.CreateRequest(knownLeaf, issuer.Cert, nil)
	if err != nil {
		t.Fatalf("ocsp.CreateRequest(known): %v", err)
	}
	respDER, err := responder.Respond(context.Background(), knownReq)
	if err != nil {
		t.Fatalf("Respond(known): %v", err)
	}
	resp, err := ocsp.ParseResponse(respDER, issuer.Cert)
	if err != nil {
		t.Fatalf("ocsp.ParseResponse(known): %v", err)
	}
	if resp.Status != ocsp.Good {
		t.Errorf("known serial status = %d, want Good (%d)", resp.Status, ocsp.Good)
	}

	unknownReq, err := ocsp.CreateRequest(unknownLeaf, issuer.Cert, nil)
	if err != nil {
		t.Fatalf("ocsp.CreateRequest(unknown): %v", err)
	}
	respDER, err = responder.Respond(context.Background(), unknownReq)
	if err != nil {
		t.Fatalf("Respond(unknown): %v", err)
	}
	resp, err = ocsp.ParseResponse(respDER, issuer.Cert)
	if err != nil {
		t.Fatalf("ocsp.ParseResponse(unknown): %v", err)
	}
	if resp.Status != ocsp.Unknown {
		t.Errorf("unknown serial status = %d, want Unknown (%d)", resp.Status, ocsp.Unknown)
	}
}

func TestOCSPResponderRevoked(t *testing.T) {
	issuer := testIssuer(t)

	st, err := sqlite.Open(filepath.Join(t.TempDir(), "trustmate.db"))
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	if err := st.Certificates().Create(context.Background(), store.CertificateRecord{
		Serial:    issuer.Cert.SerialNumber.String(),
		Kind:      store.CertKindIntermediate,
		Subject:   issuer.Cert.Subject.String(),
		NotBefore: issuer.Cert.NotBefore,
		NotAfter:  issuer.Cert.NotAfter,
		PEM:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Cert.Raw}),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Certificates().Create(intermediate): %v", err)
	}

	leaf := testLeaf(t, issuer, "revoked-leaf")
	if err := st.Certificates().Create(context.Background(), store.CertificateRecord{
		Serial:       leaf.SerialNumber.String(),
		Kind:         store.CertKindLeaf,
		Subject:      leaf.Subject.String(),
		IssuerSerial: issuer.Cert.SerialNumber.String(),
		NotBefore:    leaf.NotBefore,
		NotAfter:     leaf.NotAfter,
		PEM:          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Certificates().Create: %v", err)
	}
	if err := st.Certificates().Revoke(context.Background(), leaf.SerialNumber.String(), "keyCompromise", time.Now()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	responder := NewOCSPResponder([]pki.Issuer{issuer}, st.Certificates())
	reqDER, err := ocsp.CreateRequest(leaf, issuer.Cert, nil)
	if err != nil {
		t.Fatalf("ocsp.CreateRequest: %v", err)
	}
	respDER, err := responder.Respond(context.Background(), reqDER)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	resp, err := ocsp.ParseResponse(respDER, issuer.Cert)
	if err != nil {
		t.Fatalf("ocsp.ParseResponse: %v", err)
	}
	if resp.Status != ocsp.Revoked {
		t.Errorf("status = %d, want Revoked (%d)", resp.Status, ocsp.Revoked)
	}
}

// TestOCSPResponderSignsPerIssuer verifies a single responder configured
// with both the root and intermediate issuers signs each response with
// whichever one the request actually names, and scopes "good"/"unknown"
// to that issuer's own issuance -- the OCSP analogue of
// TestCRLBuilderScopesEntriesToOwnIssuer. A request about the
// intermediate cert (issued by root) must come back signed by root, not
// by the intermediate itself, mirroring the CRLDP fix in
// internal/bootstrap/bootstrap.go's generateIntermediate.
func TestOCSPResponderSignsPerIssuer(t *testing.T) {
	root, inter := testRootAndIntermediateIssuers(t)
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "trustmate.db"))
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	if err := st.Certificates().Create(context.Background(), store.CertificateRecord{
		Serial:    root.Cert.SerialNumber.String(),
		Kind:      store.CertKindRoot,
		Subject:   root.Cert.Subject.String(),
		NotBefore: root.Cert.NotBefore,
		NotAfter:  root.Cert.NotAfter,
		PEM:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Cert.Raw}),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Certificates().Create(root): %v", err)
	}
	if err := st.Certificates().Create(context.Background(), store.CertificateRecord{
		Serial:       inter.Cert.SerialNumber.String(),
		Kind:         store.CertKindIntermediate,
		Subject:      inter.Cert.Subject.String(),
		IssuerSerial: root.Cert.SerialNumber.String(),
		NotBefore:    inter.Cert.NotBefore,
		NotAfter:     inter.Cert.NotAfter,
		PEM:          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter.Cert.Raw}),
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Certificates().Create(intermediate): %v", err)
	}

	leaf := testLeaf(t, inter, "leaf")
	if err := st.Certificates().Create(context.Background(), store.CertificateRecord{
		Serial:       leaf.SerialNumber.String(),
		Kind:         store.CertKindLeaf,
		Subject:      leaf.Subject.String(),
		IssuerSerial: inter.Cert.SerialNumber.String(),
		NotBefore:    leaf.NotBefore,
		NotAfter:     leaf.NotAfter,
		PEM:          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Certificates().Create(leaf): %v", err)
	}

	responder := NewOCSPResponder([]pki.Issuer{root, inter}, st.Certificates())

	// A request about the intermediate cert names root as issuer -- must
	// come back signed by root, status Good.
	interReq, err := ocsp.CreateRequest(inter.Cert, root.Cert, nil)
	if err != nil {
		t.Fatalf("ocsp.CreateRequest(intermediate): %v", err)
	}
	respDER, err := responder.Respond(context.Background(), interReq)
	if err != nil {
		t.Fatalf("Respond(intermediate): %v", err)
	}
	resp, err := ocsp.ParseResponse(respDER, root.Cert)
	if err != nil {
		t.Fatalf("ocsp.ParseResponse(intermediate) against root: %v", err)
	}
	if resp.Status != ocsp.Good {
		t.Errorf("intermediate cert status = %d, want Good (%d)", resp.Status, ocsp.Good)
	}

	// A request about the leaf names the intermediate as issuer -- must
	// come back signed by the intermediate, status Good.
	leafReq, err := ocsp.CreateRequest(leaf, inter.Cert, nil)
	if err != nil {
		t.Fatalf("ocsp.CreateRequest(leaf): %v", err)
	}
	respDER, err = responder.Respond(context.Background(), leafReq)
	if err != nil {
		t.Fatalf("Respond(leaf): %v", err)
	}
	resp, err = ocsp.ParseResponse(respDER, inter.Cert)
	if err != nil {
		t.Fatalf("ocsp.ParseResponse(leaf) against intermediate: %v", err)
	}
	if resp.Status != ocsp.Good {
		t.Errorf("leaf status = %d, want Good (%d)", resp.Status, ocsp.Good)
	}

	// The leaf's serial asked about under the ROOT issuer must not come
	// back "good" signed by root -- the leaf isn't root's issuance, so
	// this must resolve to Unknown even though the serial exists in the
	// store under a different issuer.
	crossReq, err := ocsp.CreateRequest(leaf, root.Cert, nil)
	if err != nil {
		t.Fatalf("ocsp.CreateRequest(leaf under root): %v", err)
	}
	respDER, err = responder.Respond(context.Background(), crossReq)
	if err != nil {
		t.Fatalf("Respond(leaf under root): %v", err)
	}
	resp, err = ocsp.ParseResponse(respDER, root.Cert)
	if err != nil {
		t.Fatalf("ocsp.ParseResponse(leaf under root) against root: %v", err)
	}
	if resp.Status != ocsp.Unknown {
		t.Errorf("leaf-under-root status = %d, want Unknown (%d)", resp.Status, ocsp.Unknown)
	}
}

// TestOCSPResponderUnauthorizedForUnknownIssuer verifies a request
// naming an issuer this responder doesn't hold a key for gets RFC 6960's
// unsigned "unauthorized" error response, rather than being answered
// (incorrectly) with one of our own issuers' signatures.
func TestOCSPResponderUnauthorizedForUnknownIssuer(t *testing.T) {
	issuer := testIssuer(t)
	foreign := testIssuer(t)
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "trustmate.db"))
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	responder := NewOCSPResponder([]pki.Issuer{issuer}, st.Certificates())

	leaf := testLeaf(t, foreign, "leaf-under-foreign-ca")
	reqDER, err := ocsp.CreateRequest(leaf, foreign.Cert, nil)
	if err != nil {
		t.Fatalf("ocsp.CreateRequest: %v", err)
	}
	respDER, err := responder.Respond(context.Background(), reqDER)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if !bytes.Equal(respDER, ocsp.UnauthorizedErrorResponse) {
		t.Errorf("Respond(unrecognized issuer) = %x, want UnauthorizedErrorResponse", respDER)
	}
}

func TestOCSPResponderRejectsMalformedRequest(t *testing.T) {
	issuer := testIssuer(t)
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "trustmate.db"))
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	responder := NewOCSPResponder([]pki.Issuer{issuer}, st.Certificates())
	if _, err := responder.Respond(context.Background(), []byte("not an ocsp request")); err == nil {
		t.Fatal("Respond on garbage input returned nil error, want error")
	}
}
