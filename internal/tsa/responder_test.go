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
	"sync"
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

// testTSALeaf issues a TSA leaf certificate under interIssuer -- used by
// the rotation test to mint a second TSA identity chaining to the same
// intermediate the first one did, mirroring what a real rotation does
// (only the TSA leaf changes, never the intermediate).
func testTSALeaf(t *testing.T, interIssuer pki.Issuer, cn string) pki.Issuer {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert, err := pki.IssueLeaf(profiles.TSA(), pkix.Name{CommonName: cn}, signer.Public(),
		interIssuer, now, now.Add(time.Hour), nil)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	return pki.Issuer{Cert: cert, Signer: signer}
}

func TestResponderRotateSwapsSigningIdentity(t *testing.T) {
	rootSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root, err := pki.SelfSignedCA(pki.CertRequest{
		Subject: pkix.Name{CommonName: "Test Root"}, NotBefore: now, NotAfter: now.Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, rootSigner)
	if err != nil {
		t.Fatalf("SelfSignedCA: %v", err)
	}
	interSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := pki.IssueCA(pki.CertRequest{
		Subject: pkix.Name{CommonName: "Test Intermediate"}, PublicKey: interSigner.Public(),
		NotBefore: now, NotAfter: now.Add(time.Hour), IsCA: true, PathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, pki.Issuer{Cert: root, Signer: rootSigner})
	if err != nil {
		t.Fatalf("IssueCA: %v", err)
	}
	interIssuer := pki.Issuer{Cert: inter, Signer: interSigner}

	tsaIssuer := testTSALeaf(t, interIssuer, "Test TSA 1")
	r := NewResponder(tsaIssuer, inter)

	if got := r.CurrentIssuer(); got.Cert.SerialNumber.Cmp(tsaIssuer.Cert.SerialNumber) != 0 {
		t.Fatalf("CurrentIssuer before Rotate = serial %v, want %v", got.Cert.SerialNumber, tsaIssuer.Cert.SerialNumber)
	}

	reqDER := mustRequest(t, &timestamp.RequestOptions{Hash: crypto.SHA256, Certificates: true})
	respBefore, err := r.Respond(context.Background(), reqDER)
	if err != nil {
		t.Fatalf("Respond (before rotate): %v", err)
	}
	tsBefore, err := timestamp.ParseResponse(respBefore)
	if err != nil {
		t.Fatalf("ParseResponse (before rotate): %v", err)
	}
	if !tsBefore.Certificates[0].Equal(tsaIssuer.Cert) {
		t.Errorf("pre-rotation response embedded a different cert than expected")
	}

	newIssuer := testTSALeaf(t, interIssuer, "Test TSA 2")
	r.Rotate(newIssuer)

	if got := r.CurrentIssuer(); got.Cert.SerialNumber.Cmp(newIssuer.Cert.SerialNumber) != 0 {
		t.Fatalf("CurrentIssuer after Rotate = serial %v, want %v", got.Cert.SerialNumber, newIssuer.Cert.SerialNumber)
	}

	respAfter, err := r.Respond(context.Background(), reqDER)
	if err != nil {
		t.Fatalf("Respond (after rotate): %v", err)
	}
	tsAfter, err := timestamp.ParseResponse(respAfter)
	if err != nil {
		t.Fatalf("ParseResponse (after rotate): %v", err)
	}
	if !tsAfter.Certificates[0].Equal(newIssuer.Cert) {
		t.Errorf("post-rotation response did not embed the new TSA cert")
	}
	if tsAfter.Certificates[0].Equal(tsaIssuer.Cert) {
		t.Errorf("post-rotation response still embedded the old TSA cert")
	}
}

func TestResponderConcurrentRespondAndRotate(t *testing.T) {
	tsaIssuer, inter := testChain(t)
	r := NewResponder(tsaIssuer, inter)
	reqDER := mustRequest(t, &timestamp.RequestOptions{Hash: crypto.SHA256})

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				if _, err := r.Respond(context.Background(), reqDER); err != nil {
					t.Errorf("concurrent Respond: %v", err)
					return
				}
			}
		}
	}()

	for i := 0; i < 20; i++ {
		newIssuer, _ := testChain(t)
		r.Rotate(newIssuer)
		_ = r.CurrentIssuer()
	}
	close(stop)
	wg.Wait()
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
