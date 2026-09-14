// Package keystoretest is a shared behavioral contract test suite for
// keystore.KeyStore implementations. internal/keystore's FileKeyStore
// and VaultKeyStore tests both run it against a fresh store instance, so
// the two backends can't silently drift in behavior (e.g. Generate's
// no-overwrite guarantee, which keystore.FreshRef's rotation flow
// depends on).
package keystoretest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/prampec/trustmate/internal/keystore"
)

// Run executes the full contract suite against ks, deriving a distinct,
// not-already-existing key reference for each subtest from prefix (each
// subtest calls Generate at least once, and Generate must never
// overwrite an existing ref -- reusing one ref across subtests would
// make later subtests fail for the wrong reason).
func Run(t *testing.T, ks keystore.KeyStore, prefix keystore.KeyRef) {
	t.Helper()
	t.Run("ExistsBeforeAndAfterGenerate", func(t *testing.T) { testExists(t, ks, prefix+"-exists") })
	t.Run("GenerateGetRoundTrip", func(t *testing.T) { testGenerateGetRoundTrip(t, ks, prefix+"-roundtrip") })
	t.Run("GenerateExistingRefErrors", func(t *testing.T) { testGenerateExistingRefErrors(t, ks, prefix+"-noclobber") })
	t.Run("GenerateConcurrentSameRefOnlyOneSucceeds", func(t *testing.T) { testGenerateConcurrentSameRef(t, ks, prefix+"-concurrent") })
	t.Run("SignProducesVerifiableSignature", func(t *testing.T) { testSignVerifiable(t, ks, prefix+"-sign") })
}

func testExists(t *testing.T, ks keystore.KeyStore, ref keystore.KeyRef) {
	ctx := context.Background()
	if ok, err := ks.Exists(ctx, ref); err != nil || ok {
		t.Fatalf("Exists before Generate = %v, %v; want false, nil", ok, err)
	}
	if _, err := ks.Generate(ctx, ref, keystore.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	if ok, err := ks.Exists(ctx, ref); err != nil || !ok {
		t.Fatalf("Exists after Generate = %v, %v; want true, nil", ok, err)
	}
}

func testGenerateGetRoundTrip(t *testing.T, ks keystore.KeyStore, ref keystore.KeyRef) {
	ctx := context.Background()
	signer, err := ks.Generate(ctx, ref, keystore.AlgorithmECDSAP256)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ks.Get(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if !signer.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(got.Public()) {
		t.Error("Get returned a signer with a different public key than Generate")
	}
}

func testGenerateExistingRefErrors(t *testing.T, ks keystore.KeyStore, ref keystore.KeyRef) {
	ctx := context.Background()
	if _, err := ks.Generate(ctx, ref, keystore.AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Generate(ctx, ref, keystore.AlgorithmECDSAP256); err == nil {
		t.Fatal("second Generate on existing ref returned nil error, want error (must never overwrite)")
	}
}

// testGenerateConcurrentSameRef is the regression test for the TOCTOU
// race a code review caught: Generate's no-clobber guarantee is an
// Exists check followed by a create, which is only atomic if the two
// steps are serialized against a concurrent Generate for the same ref --
// see keystore.refLocker. Exactly one of many concurrent Generate calls
// for the same, previously-unused ref must succeed.
func testGenerateConcurrentSameRef(t *testing.T, ks keystore.KeyStore, ref keystore.KeyRef) {
	ctx := context.Background()

	const attempts = 8
	var wg sync.WaitGroup
	var successCount int32
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ks.Generate(ctx, ref, keystore.AlgorithmECDSAP256); err == nil {
				atomic.AddInt32(&successCount, 1)
			}
		}()
	}
	wg.Wait()

	if successCount != 1 {
		t.Errorf("successful Generate count under concurrent Generate of the same ref = %d, want exactly 1", successCount)
	}
}

// testSignVerifiable is the contract that actually matters for a KMS
// backend like Vault: the signature Sign() returns over a request built
// exactly the way crypto/x509.CreateCertificate builds one (a raw SHA-256
// digest, ASN.1 DER-encoded ECDSA signature) must verify against the
// signer's own Public() key.
func testSignVerifiable(t *testing.T, ks keystore.KeyStore, ref keystore.KeyRef) {
	ctx := context.Background()
	signer, err := ks.Generate(ctx, ref, keystore.AlgorithmECDSAP256)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte("keystoretest message"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() returned %T, want *ecdsa.PublicKey", signer.Public())
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Error("signature does not verify against the signer's own public key")
	}
}
