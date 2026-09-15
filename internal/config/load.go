package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load starts from Defaults() and, if path is non-empty, overlays a YAML
// file onto it. An empty path is not an error (no file configured); an
// explicitly set path that doesn't exist is.
func Load(path string) (Config, error) {
	cfg := Defaults()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: reading %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("config: parsing %s: %w", path, err)
	}
	if err := validate(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// LoadFromEnv is Load(path) followed by ApplyEnvOverrides.
func LoadFromEnv(path string) (Config, error) {
	cfg, err := Load(path)
	if err != nil {
		return Config{}, err
	}
	ApplyEnvOverrides(&cfg)
	if err := validate(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// ApplyEnvOverrides overlays recognized TRUSTMATE_* environment variables
// onto cfg, taking precedence over whatever Defaults()/Load() produced.
// The keystore passphrase (KEK) is deliberately NOT handled here -- see
// keystore.LoadKEK -- so it never passes through this struct.
func ApplyEnvOverrides(cfg *Config) {
	strVar(&cfg.InstanceName, "TRUSTMATE_INSTANCE_NAME")
	strVar(&cfg.Server.ListenAddr, "TRUSTMATE_LISTEN_ADDR")
	strSliceVar(&cfg.Server.TLSSANs, "TRUSTMATE_TLS_SANS")
	strVar(&cfg.Server.PublicBaseURL, "TRUSTMATE_PUBLIC_BASE_URL")
	strVar(&cfg.Log.Level, "TRUSTMATE_LOG_LEVEL")
	boolVar(&cfg.Modules.Revocation, "TRUSTMATE_ENABLE_REVOCATION")
	boolVar(&cfg.Modules.TSA, "TRUSTMATE_ENABLE_TSA")
	boolVar(&cfg.Modules.ACME, "TRUSTMATE_ENABLE_ACME")
	strVar(&cfg.Store.Driver, "TRUSTMATE_STORE_DRIVER")
	strVar(&cfg.Store.DSN, "TRUSTMATE_STORE_DSN")
	strVar(&cfg.Keystore.Driver, "TRUSTMATE_KEYSTORE_DRIVER")
	strVar(&cfg.Keystore.Dir, "TRUSTMATE_KEYSTORE_DIR")
	strVar(&cfg.Keystore.Vault.Address, "TRUSTMATE_VAULT_ADDR")
	strVar(&cfg.Keystore.Vault.TransitMount, "TRUSTMATE_VAULT_TRANSIT_MOUNT")
	strVar(&cfg.Keystore.PKCS11.ModulePath, "TRUSTMATE_PKCS11_MODULE_PATH")
	strVar(&cfg.Keystore.PKCS11.TokenLabel, "TRUSTMATE_PKCS11_TOKEN_LABEL")
	intPtrVar(&cfg.Keystore.PKCS11.SlotNumber, "TRUSTMATE_PKCS11_SLOT_NUMBER")
	strVar(&cfg.Bootstrap.OutputDir, "TRUSTMATE_BOOTSTRAP_OUTPUT_DIR")
	strVar(&cfg.Profiles.Dir, "TRUSTMATE_PROFILES_DIR")
}

func validate(cfg *Config) error {
	switch cfg.Store.Driver {
	case "sqlite", "postgres":
	default:
		return fmt.Errorf("config: unsupported store driver %q (must be \"sqlite\" or \"postgres\")", cfg.Store.Driver)
	}
	switch cfg.Keystore.Driver {
	case "file", "vault", "pkcs11":
	default:
		return fmt.Errorf("config: unsupported keystore driver %q (must be \"file\", \"vault\", or \"pkcs11\")", cfg.Keystore.Driver)
	}
	if cfg.Keystore.PKCS11.TokenLabel != "" && cfg.Keystore.PKCS11.SlotNumber != nil {
		return fmt.Errorf("config: keystore.pkcs11.token_label and slot_number are mutually exclusive (a token is selected by one or the other)")
	}
	u, err := url.Parse(cfg.Server.PublicBaseURL)
	if err != nil {
		return fmt.Errorf("config: server.public_base_url %q: %w", cfg.Server.PublicBaseURL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("config: server.public_base_url %q: must be an absolute URL with scheme and host", cfg.Server.PublicBaseURL)
	}
	cfg.Server.PublicBaseURL = strings.TrimRight(cfg.Server.PublicBaseURL, "/")
	return nil
}

func strVar(dst *string, key string) {
	if v, ok := os.LookupEnv(key); ok {
		*dst = v
	}
}

func strSliceVar(dst *[]string, key string) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	*dst = out
}

func boolVar(dst *bool, key string) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return
	}
	*dst = b
}

func intPtrVar(dst **int, key string) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return
	}
	*dst = &n
}
