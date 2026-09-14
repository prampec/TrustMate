//go:build pkcs11

package keystore

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"fmt"

	"github.com/eclipse-keypont/crypto11"
)

// PKCS11KeyStore is a KeyStore backed by a PKCS#11 token -- a real HSM,
// or a software module like SoftHSM2 for testing. It is only compiled
// in when the "pkcs11" build tag is set (see
// cmd/trustmated/keystore_pkcs11.go and Dockerfile.pkcs11): PKCS#11
// requires cgo and dlopen-ing a vendor .so at runtime, which the
// project's default CGO_ENABLED=0 scratch build can't do. See
// docs/design.md's Phase 5 roadmap entry.
//
// A PKCS#11 object is identified by both a CKA_ID and a CKA_LABEL;
// crypto11 additionally requires a non-empty CKA_ID to pair a private
// key with its public half (see FindKeyPairs' doc comment), so both are
// set to the same value -- the KeyRef itself -- keeping the identifying
// scheme consistent with FileKeyStore/VaultKeyStore, which each key off
// KeyRef alone.
type PKCS11KeyStore struct {
	ctx *crypto11.Context

	locks *refLocker
}

// PKCS11Config carries the token connection settings loaded from
// config.KeystoreConfig.PKCS11. The PIN is supplied separately (see
// LoadPKCS11PIN) so it never ends up alongside a logged configuration
// struct, the same out-of-band handling LoadKEK gives the file
// keystore's passphrase.
type PKCS11Config struct {
	ModulePath string // path to the vendor's PKCS#11 .so, mounted into the container
	TokenLabel string
	SlotNumber *int
}

// NewPKCS11KeyStore opens a session against the token named by cfg
// (by label, or by slot number if SlotNumber is set -- crypto11.Config
// treats specifying both as an error, so callers must pick one),
// authenticating with pin.
func NewPKCS11KeyStore(cfg PKCS11Config, pin string) (*PKCS11KeyStore, error) {
	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:       cfg.ModulePath,
		TokenLabel: cfg.TokenLabel,
		SlotNumber: cfg.SlotNumber,
		Pin:        pin,
	})
	if err != nil {
		return nil, fmt.Errorf("keystore: configuring pkcs11 context: %w", err)
	}
	return &PKCS11KeyStore{ctx: ctx, locks: newRefLocker()}, nil
}

// Close releases the underlying PKCS#11 session pool. Not part of the
// KeyStore interface -- main.go type-asserts for an optional Close
// method so FileKeyStore/VaultKeyStore (which need no such cleanup)
// don't have to implement a no-op.
func (k *PKCS11KeyStore) Close() error {
	return k.ctx.Close()
}

func (k *PKCS11KeyStore) Exists(_ context.Context, ref KeyRef) (bool, error) {
	signers, err := k.ctx.FindKeyPairs([]byte(ref), []byte(ref))
	if err != nil {
		return false, fmt.Errorf("keystore: pkcs11 lookup of %q: %w", ref, err)
	}
	return len(signers) > 0, nil
}

func (k *PKCS11KeyStore) Generate(ctx context.Context, ref KeyRef, alg Algorithm) (crypto.Signer, error) {
	defer k.locks.lock(ref)()

	exists, err := k.Exists(ctx, ref)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("keystore: key %q already exists", ref)
	}

	id := []byte(ref)
	switch alg {
	case AlgorithmECDSAP256:
		return k.ctx.GenerateECDSAKeyPairWithLabel(id, id, elliptic.P256())
	case AlgorithmRSA2048:
		return k.ctx.GenerateRSAKeyPairWithLabel(id, id, 2048)
	default:
		return nil, fmt.Errorf("keystore: unsupported algorithm %q", alg)
	}
}

func (k *PKCS11KeyStore) Get(_ context.Context, ref KeyRef) (crypto.Signer, error) {
	signer, err := k.ctx.FindKeyPair([]byte(ref), []byte(ref))
	if err != nil {
		return nil, fmt.Errorf("keystore: key %q not found: %w", ref, err)
	}
	return signer, nil
}
