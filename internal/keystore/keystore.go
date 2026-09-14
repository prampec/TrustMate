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
	"sync"
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

// refLocker serializes each backend's Generate (an Exists check followed
// by a create, which is not atomic against a concurrent Generate for the
// same ref on any of the three backends -- see FileKeyStore's,
// VaultKeyStore's, and PKCS11KeyStore's Generate) per KeyRef, within one
// process. It intentionally does not protect against a race across
// multiple processes/replicas -- that's what store.Store.WithExclusiveLock
// is for at call sites that need it (e.g. first-run bootstrap), and a
// backend where cross-process key creation is itself concurrency-safe
// wouldn't need this at all. All three backends' Generate calls share
// this one pattern, so it's defined once here rather than three times.
type refLocker struct {
	mu    sync.Mutex
	locks map[KeyRef]*sync.Mutex
}

func newRefLocker() *refLocker {
	return &refLocker{locks: make(map[KeyRef]*sync.Mutex)}
}

// lock blocks until ref's lock is held and returns a function that
// releases it, for `defer ks.locks.lock(ref)()` at the top of Generate.
func (l *refLocker) lock(ref KeyRef) func() {
	l.mu.Lock()
	m, ok := l.locks[ref]
	if !ok {
		m = &sync.Mutex{}
		l.locks[ref] = m
	}
	l.mu.Unlock()
	m.Lock()
	return m.Unlock
}

// loadSecret is the shared out-of-band secret-loading pattern every
// KeyStore backend's credential uses: read fileEnvVar (a mounted secret,
// preferred), falling back to literalEnvVar (a literal value) if unset.
// Called directly by main.go rather than flowing through config.Config,
// so the secret never ends up alongside a logged/dumped configuration
// struct. label appears in error messages (e.g. "KEK", "vault token",
// "pkcs11 PIN").
func loadSecret(fileEnvVar, literalEnvVar, label string) (string, error) {
	if path, ok := os.LookupEnv(fileEnvVar); ok {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("keystore: reading %s: %w", fileEnvVar, err)
		}
		secret := strings.TrimRight(string(data), "\r\n")
		if secret == "" {
			return "", fmt.Errorf("keystore: %s %s is empty", fileEnvVar, path)
		}
		return secret, nil
	}
	if v, ok := os.LookupEnv(literalEnvVar); ok {
		if v == "" {
			return "", fmt.Errorf("keystore: %s is empty", literalEnvVar)
		}
		return v, nil
	}
	return "", fmt.Errorf("keystore: neither %s nor %s is set (%s)", fileEnvVar, literalEnvVar, label)
}

// LoadKEK resolves the keystore's key-encryption passphrase from
// TRUSTMATE_KEK_FILE or TRUSTMATE_KEK -- see loadSecret.
func LoadKEK() ([]byte, error) {
	secret, err := loadSecret("TRUSTMATE_KEK_FILE", "TRUSTMATE_KEK", "keystore encryption passphrase")
	if err != nil {
		return nil, err
	}
	return []byte(secret), nil
}

// LoadPKCS11PIN resolves the PKCS#11 token's user PIN from
// TRUSTMATE_PKCS11_PIN_FILE or TRUSTMATE_PKCS11_PIN -- see loadSecret.
// Declared here rather than in pkcs11keystore.go so it's available even
// in a default (non-pkcs11) build -- a deployment misconfigured to
// select the pkcs11 driver on a binary that wasn't built with it should
// fail with a clear "not compiled in" error, not a missing-PIN error
// that suggests the PIN itself is the problem.
func LoadPKCS11PIN() (string, error) {
	return loadSecret("TRUSTMATE_PKCS11_PIN_FILE", "TRUSTMATE_PKCS11_PIN", "PKCS#11 token PIN")
}
