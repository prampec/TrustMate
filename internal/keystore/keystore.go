// Package keystore abstracts over where private keys live. The v1
// implementation is an encrypted file per key; the interface leaves a
// seam for PKCS#11 or a cloud KMS later without touching CA/TSA/
// revocation logic. See docs/design.md, module 5.
package keystore

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"strings"
)

// KeyRef names a key within the keystore (e.g. "root", "intermediate",
// "server-tls"). It is never a filesystem path by itself -- implementations
// decide how a ref maps onto storage.
type KeyRef string

// Algorithm identifies the key algorithm to generate.
type Algorithm string

const (
	AlgorithmECDSAP256 Algorithm = "ecdsa-p256"
	AlgorithmRSA2048   Algorithm = "rsa-2048"
)

// KeyStore stores and retrieves private keys, identified by KeyRef.
type KeyStore interface {
	// Generate creates a new key under ref and persists it. It returns an
	// error if ref already exists -- Generate never silently overwrites
	// key material.
	Generate(ctx context.Context, ref KeyRef, alg Algorithm) (crypto.Signer, error)
	// Get loads the key stored under ref.
	Get(ctx context.Context, ref KeyRef) (crypto.Signer, error)
	// Exists reports whether a key is already stored under ref.
	Exists(ctx context.Context, ref KeyRef) (bool, error)
}

// LoadKEK resolves the keystore's key-encryption passphrase. It reads
// TRUSTMATE_KEK_FILE (a mounted secret, preferred) or, if unset,
// TRUSTMATE_KEK (a literal passphrase). This is called directly by
// main.go rather than flowing through config.Config, so the passphrase
// never ends up alongside a logged/dumped configuration struct.
func LoadKEK() ([]byte, error) {
	if path, ok := os.LookupEnv("TRUSTMATE_KEK_FILE"); ok {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("keystore: reading TRUSTMATE_KEK_FILE: %w", err)
		}
		kek := []byte(strings.TrimRight(string(data), "\r\n"))
		if len(kek) == 0 {
			return nil, fmt.Errorf("keystore: TRUSTMATE_KEK_FILE %s is empty", path)
		}
		return kek, nil
	}
	if v, ok := os.LookupEnv("TRUSTMATE_KEK"); ok {
		if v == "" {
			return nil, fmt.Errorf("keystore: TRUSTMATE_KEK is empty")
		}
		return []byte(v), nil
	}
	return nil, fmt.Errorf("keystore: neither TRUSTMATE_KEK_FILE nor TRUSTMATE_KEK is set")
}
