//go:build pkcs11

package keystore_test

import (
	"os"
	"testing"

	"github.com/prampec/trustmate/internal/keystore"
	"github.com/prampec/trustmate/internal/keystore/keystoretest"
)

// TestPKCS11KeyStoreContract runs the shared keystore.KeyStore
// behavioral suite against a real PKCS#11 token, skipping cleanly when
// one isn't configured. SoftHSM2 (a software PKCS#11 module) is the
// standard way to exercise this without real HSM hardware, but isn't
// installed in the default dev/agent sandbox -- see AGENTS.md. CI's
// pkcs11 job (see .github/workflows/ci.yml) installs and initializes a
// SoftHSM2 token and sets these env vars.
func TestPKCS11KeyStoreContract(t *testing.T) {
	modulePath := os.Getenv("TRUSTMATE_PKCS11_TEST_MODULE_PATH")
	tokenLabel := os.Getenv("TRUSTMATE_PKCS11_TEST_TOKEN_LABEL")
	pin := os.Getenv("TRUSTMATE_PKCS11_TEST_PIN")
	if modulePath == "" || tokenLabel == "" || pin == "" {
		t.Skip("TRUSTMATE_PKCS11_TEST_MODULE_PATH/TOKEN_LABEL/PIN not set; skipping PKCS#11-backed test")
	}

	ks, err := keystore.NewPKCS11KeyStore(keystore.PKCS11Config{
		ModulePath: modulePath,
		TokenLabel: tokenLabel,
	}, pin)
	if err != nil {
		t.Fatalf("NewPKCS11KeyStore: %v", err)
	}
	t.Cleanup(func() { ks.Close() })

	keystoretest.Run(t, ks, "ci-pkcs11-key")
}
