package keystore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// freshRefAttempts bounds FreshRef's retry loop. It exists purely as a
// sanity check against a broken KeyStore.Exists implementation --
// with 4 random bytes of suffix, a genuine collision is not a realistic
// concern.
const freshRefAttempts = 5

// FreshRef returns a KeyRef starting with prefix, suffixed with random
// hex, that ks does not yet have a key stored under -- for rotation
// flows, where KeyStore.Generate refuses to overwrite an existing ref
// (see FileKeyStore.Generate), so each new signing identity needs its
// own never-before-used ref. The Exists check here is a sanity check,
// not the actual collision authority -- Generate's own internal check is
// -- so callers should propagate a Generate error rather than retry
// through FreshRef again.
func FreshRef(ctx context.Context, ks KeyStore, prefix string) (KeyRef, error) {
	for i := 0; i < freshRefAttempts; i++ {
		buf := make([]byte, 4)
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("keystore: generating ref suffix: %w", err)
		}
		ref := KeyRef(prefix + "-" + hex.EncodeToString(buf))
		exists, err := ks.Exists(ctx, ref)
		if err != nil {
			return "", fmt.Errorf("keystore: checking ref %q: %w", ref, err)
		}
		if !exists {
			return ref, nil
		}
	}
	return "", fmt.Errorf("keystore: could not find an unused ref with prefix %q after %d attempts", prefix, freshRefAttempts)
}
