//go:build pkcs11

package main

import (
	"github.com/prampec/trustmate/internal/config"
	"github.com/prampec/trustmate/internal/keystore"
)

// newPKCS11KeyStore is only compiled into binaries built with
// `-tags pkcs11` (see Dockerfile.pkcs11). See keystore_nopkcs11.go for
// the stub used in the default build.
func newPKCS11KeyStore(cfg config.PKCS11KeystoreConfig) (keystore.KeyStore, error) {
	pin, err := keystore.LoadPKCS11PIN()
	if err != nil {
		return nil, err
	}
	return keystore.NewPKCS11KeyStore(keystore.PKCS11Config{
		ModulePath: cfg.ModulePath,
		TokenLabel: cfg.TokenLabel,
		SlotNumber: cfg.SlotNumber,
	}, pin)
}
