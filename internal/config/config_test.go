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
	if err := os.WriteFile(path, []byte("store:\n  driver: mysql\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load with unsupported driver returned nil error, want error")
	}
}

func TestLoadPostgresDriverAccepted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("store:\n  driver: postgres\n  dsn: postgres://localhost/trustmate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load with store.driver=postgres: %v", err)
	}
	if cfg.Store.Driver != "postgres" {
		t.Errorf("Store.Driver = %q, want postgres", cfg.Store.Driver)
	}
}

func TestLoadUnsupportedKeystoreDriverErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("keystore:\n  driver: aws-kms\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load with unsupported keystore driver returned nil error, want error")
	}
}

func TestLoadPKCS11KeystoreDriverAccepted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yamlContent := "keystore:\n  driver: pkcs11\n  pkcs11:\n    module_path: /usr/lib/softhsm/libsofthsm2.so\n    token_label: trustmate\n"
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load with keystore.driver=pkcs11: %v", err)
	}
	if cfg.Keystore.Driver != "pkcs11" {
		t.Errorf("Keystore.Driver = %q, want pkcs11", cfg.Keystore.Driver)
	}
	if cfg.Keystore.PKCS11.TokenLabel != "trustmate" {
		t.Errorf("Keystore.PKCS11.TokenLabel = %q, want trustmate", cfg.Keystore.PKCS11.TokenLabel)
	}
}

func TestLoadPKCS11TokenLabelAndSlotNumberMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yamlContent := "keystore:\n  driver: pkcs11\n  pkcs11:\n    token_label: trustmate\n    slot_number: 0\n"
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load with both pkcs11 token_label and slot_number set returned nil error, want error")
	}
}

func TestApplyEnvOverridesPKCS11SlotNumber(t *testing.T) {
	cfg := Defaults()
	t.Setenv("TRUSTMATE_PKCS11_SLOT_NUMBER", "3")
	ApplyEnvOverrides(&cfg)
	if cfg.Keystore.PKCS11.SlotNumber == nil || *cfg.Keystore.PKCS11.SlotNumber != 3 {
		t.Errorf("Keystore.PKCS11.SlotNumber = %v, want *3", cfg.Keystore.PKCS11.SlotNumber)
	}
}

func TestLoadVaultKeystoreDriverAccepted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yamlContent := "keystore:\n  driver: vault\n  vault:\n    address: https://vault.example.com\n    transit_mount: transit\n"
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load with keystore.driver=vault: %v", err)
	}
	if cfg.Keystore.Driver != "vault" {
		t.Errorf("Keystore.Driver = %q, want vault", cfg.Keystore.Driver)
	}
	if cfg.Keystore.Vault.Address != "https://vault.example.com" {
		t.Errorf("Keystore.Vault.Address = %q, want https://vault.example.com", cfg.Keystore.Vault.Address)
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

func TestDefaultInstanceNameDerivesCommonNames(t *testing.T) {
	cfg := Defaults()
	if cfg.InstanceName != "TrustMate" {
		t.Errorf("InstanceName = %q, want TrustMate", cfg.InstanceName)
	}
	if got, want := cfg.RootCommonName(), "TrustMate Root CA"; got != want {
		t.Errorf("RootCommonName() = %q, want %q", got, want)
	}
	if got, want := cfg.IntermediateCommonName(), "TrustMate Intermediate CA"; got != want {
		t.Errorf("IntermediateCommonName() = %q, want %q", got, want)
	}
	if got, want := cfg.AdminCommonName(), "TrustMate Admin Access"; got != want {
		t.Errorf("AdminCommonName() = %q, want %q", got, want)
	}
	if got, want := cfg.ServerCommonName(), "TrustMate REST API"; got != want {
		t.Errorf("ServerCommonName() = %q, want %q", got, want)
	}
	if got, want := cfg.TSACommonName(), "TrustMate TSA"; got != want {
		t.Errorf("TSACommonName() = %q, want %q", got, want)
	}
}

func TestApplyEnvOverridesInstanceName(t *testing.T) {
	cfg := Defaults()
	t.Setenv("TRUSTMATE_INSTANCE_NAME", "Example Corp CA")
	ApplyEnvOverrides(&cfg)

	if cfg.InstanceName != "Example Corp CA" {
		t.Errorf("InstanceName = %q, want Example Corp CA", cfg.InstanceName)
	}
	if got, want := cfg.RootCommonName(), "Example Corp CA Root CA"; got != want {
		t.Errorf("RootCommonName() = %q, want %q", got, want)
	}
	if got, want := cfg.TSACommonName(), "Example Corp CA TSA"; got != want {
		t.Errorf("TSACommonName() = %q, want %q", got, want)
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
