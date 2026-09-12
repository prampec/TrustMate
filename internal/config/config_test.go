package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEmptyPathUsesDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") returned error: %v", err)
	}
	if cfg.Server.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want :8080", cfg.Server.ListenAddr)
	}
	if cfg.Store.Driver != "sqlite" {
		t.Errorf("Store.Driver = %q, want sqlite", cfg.Store.Driver)
	}
}

func TestLoadMissingExplicitPathErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Fatal("Load with missing explicit path returned nil error, want error")
	}
}

func TestLoadFileOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yamlContent := "server:\n  listen_addr: \":9090\"\nlog:\n  level: DEBUG\n"
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Server.ListenAddr != ":9090" {
		t.Errorf("ListenAddr = %q, want :9090", cfg.Server.ListenAddr)
	}
	if cfg.Log.Level != "DEBUG" {
		t.Errorf("Log.Level = %q, want DEBUG", cfg.Log.Level)
	}
	// Untouched-by-file fields keep their defaults.
	if cfg.Store.Driver != "sqlite" {
		t.Errorf("Store.Driver = %q, want sqlite (untouched default)", cfg.Store.Driver)
	}
}

func TestLoadMalformedYAMLErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server: [this is not valid: yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load with malformed YAML returned nil error, want error")
	}
}

func TestLoadUnsupportedDriverErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("store:\n  driver: postgres\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load with unsupported driver returned nil error, want error")
	}
}

func TestLoadInvalidPublicBaseURLErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  public_base_url: \"not-a-url\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load with schemeless public_base_url returned nil error, want error")
	}
}

func TestLoadTrimsTrailingSlashFromPublicBaseURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  public_base_url: \"https://ca.example.com/\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Server.PublicBaseURL != "https://ca.example.com" {
		t.Errorf("PublicBaseURL = %q, want https://ca.example.com (trailing slash trimmed)", cfg.Server.PublicBaseURL)
	}
}

func TestApplyEnvOverridesPublicBaseURL(t *testing.T) {
	t.Setenv("TRUSTMATE_PUBLIC_BASE_URL", "https://ca.example.com")
	cfg, err := LoadFromEnv("")
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if cfg.Server.PublicBaseURL != "https://ca.example.com" {
		t.Errorf("PublicBaseURL = %q, want https://ca.example.com", cfg.Server.PublicBaseURL)
	}
}

func TestApplyEnvOverridesPrecedence(t *testing.T) {
	// default < file < env
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  listen_addr: \":9090\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("TRUSTMATE_LISTEN_ADDR", ":7070")
	t.Setenv("TRUSTMATE_LOG_LEVEL", "WARN")
	t.Setenv("TRUSTMATE_ENABLE_TSA", "false")

	cfg, err := LoadFromEnv(path)
	if err != nil {
		t.Fatalf("LoadFromEnv returned error: %v", err)
	}
	if cfg.Server.ListenAddr != ":7070" {
		t.Errorf("ListenAddr = %q, want :7070 (env should beat file)", cfg.Server.ListenAddr)
	}
	if cfg.Log.Level != "WARN" {
		t.Errorf("Log.Level = %q, want WARN (env should beat default)", cfg.Log.Level)
	}
	if cfg.Modules.TSA {
		t.Errorf("Modules.TSA = true, want false (env override)")
	}
	if !cfg.Modules.Revocation {
		t.Errorf("Modules.Revocation = false, want true (default, untouched)")
	}
}

func TestApplyEnvOverridesTLSSANs(t *testing.T) {
	cfg := Defaults()
	t.Setenv("TRUSTMATE_TLS_SANS", "api.example.com, api2.example.com ,")
	ApplyEnvOverrides(&cfg)
	want := []string{"api.example.com", "api2.example.com"}
	if len(cfg.Server.TLSSANs) != len(want) {
		t.Fatalf("TLSSANs = %v, want %v", cfg.Server.TLSSANs, want)
	}
	for i := range want {
		if cfg.Server.TLSSANs[i] != want[i] {
			t.Errorf("TLSSANs[%d] = %q, want %q", i, cfg.Server.TLSSANs[i], want[i])
		}
	}
}
