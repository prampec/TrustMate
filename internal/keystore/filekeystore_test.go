package keystore

import (
	"context"
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFileKeyStoreGenerateGetRoundTrip(t *testing.T) {
	ctx := context.Background()
	ks, err := NewFileKeyStore(t.TempDir(), []byte("test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}

	signer, err := ks.Generate(ctx, "root", AlgorithmECDSAP256)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ks.Get(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	if !signer.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(got.Public()) {
		t.Error("Get returned a signer with a different public key than Generate")
	}
}

func TestFileKeyStoreGetUncachedReadsFromDisk(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ks, err := NewFileKeyStore(dir, []byte("test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := ks.Generate(ctx, "root", AlgorithmECDSAP256)
	if err != nil {
		t.Fatal(err)
	}

	// A fresh KeyStore instance (no in-memory cache) over the same dir
	// must still be able to decrypt the key.
	ks2, err := NewFileKeyStore(dir, []byte("test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ks2.Get(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	if !want.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(got.Public()) {
		t.Error("key read from disk differs from the key that was generated")
	}
}

func TestFileKeyStoreGenerateExistingRefErrors(t *testing.T) {
	ctx := context.Background()
	ks, err := NewFileKeyStore(t.TempDir(), []byte("test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Generate(ctx, "root", AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Generate(ctx, "root", AlgorithmECDSAP256); err == nil {
		t.Fatal("second Generate on existing ref returned nil error, want error (must never overwrite)")
	}
}

func TestFileKeyStoreWrongPassphraseFails(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ks, err := NewFileKeyStore(dir, []byte("correct-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Generate(ctx, "root", AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}

	wrong, err := NewFileKeyStore(dir, []byte("wrong-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Get(ctx, "root"); err == nil {
		t.Fatal("Get with wrong passphrase returned nil error, want error")
	}
}

func TestFileKeyStoreTamperedCiphertextFails(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ks, err := NewFileKeyStore(dir, []byte("test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Generate(ctx, "root", AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "root.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var kf keyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		t.Fatal(err)
	}
	kf.Ciphertext[0] ^= 0xFF
	tampered, err := json.Marshal(kf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	fresh, err := NewFileKeyStore(dir, []byte("test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Get(ctx, "root"); err == nil {
		t.Fatal("Get with tampered ciphertext returned nil error, want GCM auth failure")
	}
}

func TestFileKeyStoreExists(t *testing.T) {
	ctx := context.Background()
	ks, err := NewFileKeyStore(t.TempDir(), []byte("test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := ks.Exists(ctx, "root"); err != nil || ok {
		t.Fatalf("Exists before Generate = %v, %v; want false, nil", ok, err)
	}
	if _, err := ks.Generate(ctx, "root", AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}
	if ok, err := ks.Exists(ctx, "root"); err != nil || !ok {
		t.Fatalf("Exists after Generate = %v, %v; want true, nil", ok, err)
	}
}

func TestFileKeyStorePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits not meaningful on windows")
	}
	ctx := context.Background()
	// NewFileKeyStore must set perms itself when it creates the dir --
	// t.TempDir() already exists, so MkdirAll wouldn't touch its mode.
	dir := filepath.Join(t.TempDir(), "keys")
	ks, err := NewFileKeyStore(dir, []byte("test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Generate(ctx, "root", AlgorithmECDSAP256); err != nil {
		t.Fatal(err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir perm = %o, want 0700", perm)
	}

	fileInfo, err := os.Stat(filepath.Join(dir, "root.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file perm = %o, want 0600", perm)
	}
}
