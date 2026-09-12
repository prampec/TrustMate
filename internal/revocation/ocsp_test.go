package revocation

import (
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

	responder := NewOCSPResponder(issuer, st.Certificates())

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

func TestOCSPResponderRejectsMalformedRequest(t *testing.T) {
	issuer := testIssuer(t)
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "trustmate.db"))
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	responder := NewOCSPResponder(issuer, st.Certificates())
	if _, err := responder.Respond(context.Background(), []byte("not an ocsp request")); err == nil {
		t.Fatal("Respond on garbage input returned nil error, want error")
	}
}
