// Package acme implements the JWS (RFC 7515) and JWK (RFC 7517/7638)
// primitives an RFC 8555 ACME server needs: parsing/verifying the
// flattened-JSON request signatures ACME clients send, and computing a
// JWK thumbprint to use as an account's stable identifier. It knows
// nothing about HTTP routes or TrustMate's certificate/store types --
// see internal/api/acme.go for the handlers that wire this into the
// REST surface. See docs/design.md's Phase 5 roadmap entry.
package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// JWS is a parsed (but not yet signature-verified) flattened-JSON Web
// Signature, RFC 7515 section 7.2.2 / RFC 8555 section 6.2.
type JWS struct {
	Header       Header
	Payload      []byte // decoded payload bytes; empty for a POST-as-GET
	signingInput []byte // protected + "." + payload, exactly as transmitted -- what the signature covers
	signature    []byte
}

// Header is the subset of JWS protected-header fields ACME uses.
type Header struct {
	Alg   string          `json:"alg"`
	Nonce string          `json:"nonce"`
	URL   string          `json:"url"`
	Kid   string          `json:"kid,omitempty"`
	JWK   json.RawMessage `json:"jwk,omitempty"`
}

type flattenedJSON struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

var b64 = base64.RawURLEncoding

// ParseJWS decodes a flattened-JSON JWS request body. It does not verify
// the signature -- callers must call Verify (account-key algorithms) or
// VerifyHMAC (the EAB inner JWS) once they know which key the JWS claims
// to be signed by.
func ParseJWS(body []byte) (*JWS, error) {
	var fj flattenedJSON
	if err := json.Unmarshal(body, &fj); err != nil {
		return nil, fmt.Errorf("acme: decoding JWS envelope: %w", err)
	}
	if fj.Protected == "" || fj.Signature == "" {
		return nil, fmt.Errorf("acme: JWS missing protected header or signature")
	}

	headerJSON, err := b64.DecodeString(fj.Protected)
	if err != nil {
		return nil, fmt.Errorf("acme: decoding protected header: %w", err)
	}
	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("acme: parsing protected header: %w", err)
	}

	var payload []byte
	if fj.Payload != "" {
		payload, err = b64.DecodeString(fj.Payload)
		if err != nil {
			return nil, fmt.Errorf("acme: decoding payload: %w", err)
		}
	}
	signature, err := b64.DecodeString(fj.Signature)
	if err != nil {
		return nil, fmt.Errorf("acme: decoding signature: %w", err)
	}

	return &JWS{
		Header:       header,
		Payload:      payload,
		signingInput: []byte(fj.Protected + "." + fj.Payload),
		signature:    signature,
	}, nil
}

// Verify checks the JWS signature against pub, dispatching on
// j.Header.Alg. Supports ES256 (*ecdsa.PublicKey, P-256) and RS256
// (*rsa.PublicKey) -- the two account-key algorithms TrustMate's own
// issuance already supports (keystore.AlgorithmECDSAP256/RSA2048), kept
// consistent rather than adding JOSE algorithms TrustMate can't issue
// certificates for anyway.
func (j *JWS) Verify(pub crypto.PublicKey) error {
	switch j.Header.Alg {
	case "ES256":
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok || ecPub.Curve != elliptic.P256() {
			return fmt.Errorf("acme: ES256 JWS requires a P-256 ECDSA key")
		}
		return verifyES256(ecPub, j.signingInput, j.signature)
	case "RS256":
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("acme: RS256 JWS requires an RSA key")
		}
		digest := sha256.Sum256(j.signingInput)
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], j.signature); err != nil {
			return fmt.Errorf("acme: RS256 signature verification failed: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("acme: unsupported JWS algorithm %q (must be ES256 or RS256)", j.Header.Alg)
	}
}

// verifyES256 checks a JOSE-format (RFC 7518 section 3.4: raw r||s, not
// ASN.1 DER) ECDSA P-256 signature.
func verifyES256(pub *ecdsa.PublicKey, signingInput, sig []byte) error {
	if len(sig) != 64 {
		return fmt.Errorf("acme: ES256 signature must be 64 bytes (got %d)", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	digest := sha256.Sum256(signingInput)
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return fmt.Errorf("acme: ES256 signature verification failed")
	}
	return nil
}

// VerifyHMAC checks an HS256 JWS -- the algorithm RFC 8555 section 7.3.4
// mandates for the EAB inner JWS, signed with the shared secret an admin
// issued out-of-band rather than an account's own key.
func (j *JWS) VerifyHMAC(key []byte) error {
	if j.Header.Alg != "HS256" {
		return fmt.Errorf("acme: EAB JWS alg must be HS256, got %q", j.Header.Alg)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(j.signingInput)
	expected := mac.Sum(nil)
	if subtle.ConstantTimeCompare(expected, j.signature) != 1 {
		return fmt.Errorf("acme: HS256 signature verification failed")
	}
	return nil
}

// jwkEC and jwkRSA marshal to RFC 7638's canonical thumbprint form:
// exactly the "required members" for the key type, ordered
// lexicographically by name. Go's json.Marshal emits object fields in
// struct declaration order with no inserted whitespace, so declaring the
// fields already in that alphabetical order is sufficient -- no separate
// canonicalization pass is needed.
type jwkEC struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwkRSA struct {
	E   string `json:"e"`
	Kty string `json:"kty"`
	N   string `json:"n"`
}

// PublicKeyToJWK renders pub as its canonical (RFC 7638 thumbprint-form)
// JWK JSON, and separately as the fuller header-JWK object the client
// itself would submit (which crypto11/RFC 7517 clients also accept back
// unchanged) -- both are the same bytes here since TrustMate only ever
// needs the required members.
func PublicKeyToJWK(pub crypto.PublicKey) ([]byte, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("acme: unsupported ECDSA curve (must be P-256)")
		}
		size := 32
		return json.Marshal(jwkEC{
			Crv: "P-256",
			Kty: "EC",
			X:   b64.EncodeToString(leftPad(k.X.Bytes(), size)),
			Y:   b64.EncodeToString(leftPad(k.Y.Bytes(), size)),
		})
	case *rsa.PublicKey:
		return json.Marshal(jwkRSA{
			E:   b64.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
			Kty: "RSA",
			N:   b64.EncodeToString(k.N.Bytes()),
		})
	default:
		return nil, fmt.Errorf("acme: unsupported public key type %T", pub)
	}
}

// JWKPublicKey parses a JWK's "kty"/"crv"/"x"/"y" (EC) or "kty"/"n"/"e"
// (RSA) fields back into a crypto.PublicKey, the inverse of
// PublicKeyToJWK.
func JWKPublicKey(jwkJSON []byte) (crypto.PublicKey, error) {
	var kty struct {
		Kty string `json:"kty"`
	}
	if err := json.Unmarshal(jwkJSON, &kty); err != nil {
		return nil, fmt.Errorf("acme: parsing jwk: %w", err)
	}
	switch kty.Kty {
	case "EC":
		var j jwkEC
		if err := json.Unmarshal(jwkJSON, &j); err != nil {
			return nil, fmt.Errorf("acme: parsing EC jwk: %w", err)
		}
		if j.Crv != "P-256" {
			return nil, fmt.Errorf("acme: unsupported jwk curve %q (must be P-256)", j.Crv)
		}
		x, err := b64.DecodeString(j.X)
		if err != nil {
			return nil, fmt.Errorf("acme: decoding jwk x: %w", err)
		}
		y, err := b64.DecodeString(j.Y)
		if err != nil {
			return nil, fmt.Errorf("acme: decoding jwk y: %w", err)
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, fmt.Errorf("acme: jwk point is not on P-256")
		}
		return pub, nil
	case "RSA":
		var j jwkRSA
		if err := json.Unmarshal(jwkJSON, &j); err != nil {
			return nil, fmt.Errorf("acme: parsing RSA jwk: %w", err)
		}
		n, err := b64.DecodeString(j.N)
		if err != nil {
			return nil, fmt.Errorf("acme: decoding jwk n: %w", err)
		}
		e, err := b64.DecodeString(j.E)
		if err != nil {
			return nil, fmt.Errorf("acme: decoding jwk e: %w", err)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	default:
		return nil, fmt.Errorf("acme: unsupported jwk kty %q (must be EC or RSA)", kty.Kty)
	}
}

// Thumbprint computes the RFC 7638 JWK thumbprint (base64url, unpadded,
// of the SHA-256 digest of the canonical JWK JSON) for pub, used as an
// ACME account's stable identifier.
func Thumbprint(pub crypto.PublicKey) (string, error) {
	canonical, err := PublicKeyToJWK(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return b64.EncodeToString(sum[:]), nil
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
