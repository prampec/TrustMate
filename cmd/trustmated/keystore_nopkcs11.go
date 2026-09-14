//go:build !pkcs11

package main

import (
	"fmt"

	"github.com/prampec/trustmate/internal/config"
	"github.com/prampec/trustmate/internal/keystore"
)

// newPKCS11KeyStore is the default (non-cgo) build's stand-in: PKCS#11
// support requires cgo and dlopen-ing a vendor .so at runtime, which the
// default CGO_ENABLED=0 scratch build can't do (see docs/design.md's
// Phase 5 roadmap entry and Dockerfile.pkcs11). A deployment that
// selects keystore.driver: pkcs11 against a binary built without the
// "pkcs11" tag fails clearly here, rather than with a confusing error
// from somewhere else.
func newPKCS11KeyStore(config.PKCS11KeystoreConfig) (keystore.KeyStore, error) {
	return nil, fmt.Errorf("keystore: pkcs11 support not compiled into this binary (rebuild with -tags pkcs11)")
}
