package tsa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/digitorus/timestamp"

	"github.com/prampec/trustmate/internal/pki"
	"github.com/prampec/trustmate/internal/profiles"
)

// testChain builds a real root -> intermediate -> TSA leaf chain (mirrors
// internal/revocation's package-local testIssuer helper, which is
// unexported and thus unimportable from here).
func testChain(t *testing.T) (tsaIssuer pki.Issuer, intermediate *x509.Certificate) {
	t.Helper()

	rootSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root, err := pki.SelfSignedCA(pki.CertRequest{
		Subject:   pkix.Name{CommonName: "Test Root"},
		NotBefore: now,
		NotAfter:  now.Add(24 * time.Hour),
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, rootSigner)
	if err != nil {
		t.Fatalf("SelfSignedCA: %v", err)
	}

	interSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := pki.IssueCA(pki.CertRequest{
		Subject:     pkix.Name{CommonName: "Test Intermediate"},
		PublicKey:   interSigner.Public(),
		NotBefore:   now,
		NotAfter:    now.Add(time.Hour),
		IsCA:        true,
		PathLenZero: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, pki.Issuer{Cert: root, Signer: rootSigner})
	if err != nil {
		t.Fatalf("IssueCA: %v", err)
	}
	interIssuer := pki.Issuer{Cert: inter, Signer: interSigner}

	tsaSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tsaCert, err := pki.IssueLeaf(profiles.TSA(), pkix.Name{CommonName: "Test TSA"}, tsaSigner.Public(),
		interIssuer, now, now.Add(time.Hour), nil)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}

	return pki.Issuer{Cert: tsaCert, Signer: tsaSigner}, inter
}

func mustRequest(t *testing.T, opts *timestamp.RequestOptions) []byte {
	t.Helper()
	der, err := timestamp.CreateRequest(bytes.NewReader([]byte("hello world")), opts)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestResponderSignsChainAndEchoesNonceAndCerts(t *testing.T) {
	tsaIssuer, inter := testChain(t)
	r := NewResponder(tsaIssuer, inter)

	nonce := big.NewInt(123456789)
	reqDER := mustRequest(t, &timestamp.RequestOptions{Hash: crypto.SHA256, Certificates: true, Nonce: nonce})

	respDER, err := r.Respond(context.Background(), reqDER)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}

	ts, err := timestamp.ParseResponse(respDER)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if ts.Nonce == nil || ts.Nonce.Cmp(nonce) != 0 {
		t.Errorf("nonce = %v, want %v", ts.Nonce, nonce)
	}

	var found bool
	for _, c := range ts.Certificates {
		if c.Equal(tsaIssuer.Cert) {
			found = true
		}
	}
	if !found {
		t.Error("TSA certificate not found in response's embedded certificates")
	}
	if err := tsaIssuer.Cert.CheckSignatureFrom(inter); err != nil {
		t.Errorf("TSA cert does not chain to intermediate: %v", err)
	}
}

func TestResponderOmitsNonceAndCertsWhenNotRequested(t *testing.T) {
	tsaIssuer, inter := testChain(t)
	r := NewResponder(tsaIssuer, inter)

	reqDER := mustRequest(t, &timestamp.RequestOptions{Hash: crypto.SHA256})

	respDER, err := r.Respond(context.Background(), reqDER)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}

	ts, err := timestamp.ParseResponse(respDER)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if ts.Nonce != nil {
		t.Errorf("nonce = %v, want nil (request had none)", ts.Nonce)
	}
	if len(ts.Certificates) != 0 {
		t.Errorf("certificates = %v, want none (request did not ask for them)", ts.Certificates)
	}
}

func TestResponderMonotonicGenTime(t *testing.T) {
	tsaIssuer, inter := testChain(t)
	r := NewResponder(tsaIssuer, inter)
	reqDER := mustRequest(t, &timestamp.RequestOptions{Hash: crypto.SHA256, Certificates: true})

	resp1, err := r.Respond(context.Background(), reqDER)
	if err != nil {
		t.Fatalf("Respond (1st): %v", err)
	}
	resp2, err := r.Respond(context.Background(), reqDER)
	if err != nil {
		t.Fatalf("Respond (2nd): %v", err)
	}

	ts1, err := timestamp.ParseResponse(resp1)
	if err != nil {
		t.Fatalf("ParseResponse (1st): %v", err)
	}
	ts2, err := timestamp.ParseResponse(resp2)
	if err != nil {
		t.Fatalf("ParseResponse (2nd): %v", err)
	}
	if !ts2.Time.After(ts1.Time) {
		t.Errorf("genTime not strictly increasing: %v then %v", ts1.Time, ts2.Time)
	}
}

func TestResponderMalformedRequest(t *testing.T) {
	tsaIssuer, inter := testChain(t)
	r := NewResponder(tsaIssuer, inter)

	_, err := r.Respond(context.Background(), []byte("not a timestamp request"))
	if !errors.Is(err, ErrMalformedRequest) {
		t.Errorf("err = %v, want ErrMalformedRequest", err)
	}
}

func TestResponderRejectsSHA1(t *testing.T) {
	tsaIssuer, inter := testChain(t)
	r := NewResponder(tsaIssuer, inter)

	reqDER := mustRequest(t, &timestamp.RequestOptions{Hash: crypto.SHA1})
	_, err := r.Respond(context.Background(), reqDER)
	if !errors.Is(err, ErrUnsupportedRequest) {
		t.Errorf("err = %v, want ErrUnsupportedRequest", err)
	}
}
