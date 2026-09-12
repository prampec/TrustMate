package keystore

import (
	"context"
	"testing"
)

func TestFreshRefReturnsUnusedDistinctRefs(t *testing.T) {
	ctx := context.Background()
	ks, err := NewFileKeyStore(t.TempDir(), []byte("test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}

	first, err := FreshRef(ctx, ks, "tsa")
	if err != nil {
		t.Fatalf("FreshRef: %v", err)
	}
	if exists, err := ks.Exists(ctx, first); err != nil || exists {
		t.Fatalf("FreshRef returned a ref that already exists: %q (exists=%v, err=%v)", first, exists, err)
	}
	if _, err := ks.Generate(ctx, first, AlgorithmECDSAP256); err != nil {
		t.Fatalf("Generate(%q): %v", first, err)
	}

	second, err := FreshRef(ctx, ks, "tsa")
	if err != nil {
		t.Fatalf("FreshRef (second): %v", err)
	}
	if second == first {
		t.Fatalf("FreshRef returned the same ref twice: %q", first)
	}
	if exists, err := ks.Exists(ctx, second); err != nil || exists {
		t.Fatalf("second FreshRef returned a ref that already exists: %q (exists=%v, err=%v)", second, exists, err)
	}
}
