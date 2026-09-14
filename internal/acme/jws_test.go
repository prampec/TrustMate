package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

// signJWS builds a flattened-JSON JWS request body the way a real ACME
// client would, for use as test input -- it's the encoding half of what
// ParseJWS/Verify decode and check.
func signJWS(t *testing.T, header Header, payload []byte, sign func(signingInput []byte) []byte) []byte {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	protected := b64.EncodeToString(headerJSON)
	payloadB64 := ""
	if payload != nil {
		payloadB64 = b64.EncodeToString(payload)
	}
	signingInput := []byte(protected + "." + payloadB64)
	sig := sign(signingInput)

	body, err := json.Marshal(flattenedJSON{
		Protected: protected,
		Payload:   payloadB64,
		Signature: b64.EncodeToString(sig),
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestJWSRoundTripES256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"termsOfServiceAgreed":true}`)
	body := signJWS(t, Header{Alg: "ES256", Nonce: "test-nonce", URL: "https://example/new-account"}, payload, func(signingInput []byte) []byte {
		digest := sha256.Sum256(signingInput)
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig
	})

	jws, err := ParseJWS(body)
	if err != nil {
		t.Fatalf("ParseJWS: %v", err)
	}
	if jws.Header.Nonce != "test-nonce" || jws.Header.URL != "https://example/new-account" {
		t.Errorf("parsed header = %+v", jws.Header)
	}
	if err := jws.Verify(&priv.PublicKey); err != nil {
		t.Errorf("Verify with correct key: %v", err)
	}

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := jws.Verify(&other.PublicKey); err == nil {
		t.Error("Verify with wrong key returned nil error, want signature failure")
	}
}

func TestJWSRoundTripRS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"termsOfServiceAgreed":true}`)
	body := signJWS(t, Header{Alg: "RS256", Nonce: "test-nonce", URL: "https://example/new-account"}, payload, func(signingInput []byte) []byte {
		digest := sha256.Sum256(signingInput)
		sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return sig
	})

	jws, err := ParseJWS(body)
	if err != nil {
		t.Fatalf("ParseJWS: %v", err)
	}
	if err := jws.Verify(&priv.PublicKey); err != nil {
		t.Errorf("Verify with correct key: %v", err)
	}
}

func TestJWSVerifyHMAC(t *testing.T) {
	key := []byte("shared-eab-secret")
	payload := []byte(`{"crv":"P-256","kty":"EC","x":"...","y":"..."}`)
	body := signJWS(t, Header{Alg: "HS256", Kid: "eab-key-1", URL: "https://example/new-account"}, payload, func(signingInput []byte) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write(signingInput)
		return mac.Sum(nil)
	})

	jws, err := ParseJWS(body)
	if err != nil {
		t.Fatalf("ParseJWS: %v", err)
	}
	if err := jws.VerifyHMAC(key); err != nil {
		t.Errorf("VerifyHMAC with correct key: %v", err)
	}
	if err := jws.VerifyHMAC([]byte("wrong-secret")); err == nil {
		t.Error("VerifyHMAC with wrong key returned nil error, want failure")
	}
}

func TestJWSTamperedPayloadFailsVerification(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := signJWS(t, Header{Alg: "ES256", URL: "https://example/x"}, []byte(`{"a":1}`), func(signingInput []byte) []byte {
		digest := sha256.Sum256(signingInput)
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig
	})

	var fj flattenedJSON
	if err := json.Unmarshal(body, &fj); err != nil {
		t.Fatal(err)
	}
	fj.Payload = base64.RawURLEncoding.EncodeToString([]byte(`{"a":2}`))
	tampered, err := json.Marshal(fj)
	if err != nil {
		t.Fatal(err)
	}

	jws, err := ParseJWS(tampered)
	if err != nil {
		t.Fatalf("ParseJWS: %v", err)
	}
	if err := jws.Verify(&priv.PublicKey); err == nil {
		t.Error("Verify on a tampered payload returned nil error, want signature failure")
	}
}

// TestThumbprintMatchesRFC7638Example checks Thumbprint against RFC
// 7638's own worked example (Appendix), a strong end-to-end check that
// PublicKeyToJWK's canonical form (field set + lexicographic order + no
// whitespace) is byte-for-byte what the spec expects.
func TestThumbprintMatchesRFC7638Example(t *testing.T) {
	const (
		nB64 = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
		eB64 = "AQAB"
		want = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	)
	n, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		t.Fatal(err)
	}
	e, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		t.Fatal(err)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}

	got, err := Thumbprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("Thumbprint = %q, want %q (RFC 7638 example)", got, want)
	}
}

func TestJWKPublicKeyRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwkJSON, err := PublicKeyToJWK(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := JWKPublicKey(jwkJSON)
	if err != nil {
		t.Fatal(err)
	}
	gotEC, ok := got.(*ecdsa.PublicKey)
	if !ok || !gotEC.Equal(&priv.PublicKey) {
		t.Errorf("JWKPublicKey round trip = %+v, want %+v", got, priv.PublicKey)
	}
}
