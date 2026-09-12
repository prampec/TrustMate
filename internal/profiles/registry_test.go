package profiles

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prampec/trustmate/internal/store"
	"github.com/prampec/trustmate/internal/store/sqlite"
)

func newTestRegistryRepo(t *testing.T) store.ProfileRepository {
	t.Helper()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "trustmate.db"))
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st.Profiles()
}

func writeProfileYAML(t *testing.T, dir, filename, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNewRegistrySeedsBuiltins(t *testing.T) {
	r, err := NewRegistry(context.Background(), newTestRegistryRepo(t), "")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if len(r.All()) != len(All()) {
		t.Errorf("len(All()) = %d, want %d", len(r.All()), len(All()))
	}
	if _, ok := r.Lookup("document-signing"); !ok {
		t.Error("Lookup(document-signing) not found")
	}
}

func TestRegistryLoadsConfigProfile(t *testing.T) {
	dir := t.TempDir()
	writeProfileYAML(t, dir, "code-signing.yaml", `
name: code-signing
key_algorithm: ecdsa-p256
key_usage: [digitalSignature]
ext_key_usage: [codeSigning]
validity: 8760h
enable_ocsp: true
enable_crl: true
`)

	r, err := NewRegistry(context.Background(), newTestRegistryRepo(t), dir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	p, ok := r.Lookup("code-signing")
	if !ok {
		t.Fatal("Lookup(code-signing) not found after loading from dir")
	}
	if p.Validity != 8760*time.Hour {
		t.Errorf("Validity = %v, want 8760h", p.Validity)
	}
	if !p.EnableOCSP || !p.EnableCRL {
		t.Errorf("EnableOCSP=%v EnableCRL=%v, want both true", p.EnableOCSP, p.EnableCRL)
	}

	// Built-ins are still present alongside the loaded one.
	if _, ok := r.Lookup("document-signing"); !ok {
		t.Error("built-in document-signing profile missing after Load")
	}
}

func TestRegistryRejectsBuiltinNameCollision(t *testing.T) {
	dir := t.TempDir()
	writeProfileYAML(t, dir, "collide.yaml", `
name: document-signing
key_algorithm: ecdsa-p256
key_usage: [digitalSignature]
validity: 24h
`)

	if _, err := NewRegistry(context.Background(), newTestRegistryRepo(t), dir); err == nil {
		t.Error("NewRegistry with a built-in-colliding profile name succeeded, want error")
	}
}

func TestRegistryRejectsUnknownEnumValues(t *testing.T) {
	dir := t.TempDir()
	writeProfileYAML(t, dir, "bad.yaml", `
name: bad-profile
key_algorithm: rsa-4096
key_usage: [digitalSignature]
validity: 24h
`)

	if _, err := NewRegistry(context.Background(), newTestRegistryRepo(t), dir); err == nil {
		t.Error("NewRegistry with an unknown key_algorithm succeeded, want error")
	}
}

func TestRegistryReloadPicksUpChangesAndRemovals(t *testing.T) {
	dir := t.TempDir()
	writeProfileYAML(t, dir, "extra.yaml", `
name: extra
key_algorithm: ecdsa-p256
key_usage: [digitalSignature]
validity: 24h
`)

	repo := newTestRegistryRepo(t)
	r, err := NewRegistry(context.Background(), repo, dir)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if _, ok := r.Lookup("extra"); !ok {
		t.Fatal("Lookup(extra) not found")
	}
	firstVersion, ok := r.Lookup("extra")
	if !ok || firstVersion.Version != 1 {
		t.Fatalf("extra profile version = %+v, want version 1", firstVersion)
	}

	// Changing content on reload bumps the version.
	writeProfileYAML(t, dir, "extra.yaml", `
name: extra
key_algorithm: ecdsa-p256
key_usage: [digitalSignature, keyEncipherment]
validity: 24h
`)
	if err := r.Load(context.Background()); err != nil {
		t.Fatalf("Load (changed): %v", err)
	}
	changed, ok := r.Lookup("extra")
	if !ok || changed.Version != 2 {
		t.Fatalf("extra profile after content change = %+v, want version 2", changed)
	}

	// Removing the file removes it from the registry on next Load.
	if err := os.Remove(filepath.Join(dir, "extra.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := r.Load(context.Background()); err != nil {
		t.Fatalf("Load (removed): %v", err)
	}
	if _, ok := r.Lookup("extra"); ok {
		t.Error("Lookup(extra) still found after removing its config file and reloading")
	}
	// Built-ins survive a reload regardless.
	if _, ok := r.Lookup("document-signing"); !ok {
		t.Error("built-in document-signing profile missing after reload")
	}
}
