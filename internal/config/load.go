package config

import (
	"fmt"
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
	if err := validate(cfg); err != nil {
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
	if err := validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// ApplyEnvOverrides overlays recognized TRUSTMATE_* environment variables
// onto cfg, taking precedence over whatever Defaults()/Load() produced.
// The keystore passphrase (KEK) is deliberately NOT handled here -- see
// keystore.LoadKEK -- so it never passes through this struct.
func ApplyEnvOverrides(cfg *Config) {
	strVar(&cfg.Server.ListenAddr, "TRUSTMATE_LISTEN_ADDR")
	strSliceVar(&cfg.Server.TLSSANs, "TRUSTMATE_TLS_SANS")
	strVar(&cfg.Log.Level, "TRUSTMATE_LOG_LEVEL")
	boolVar(&cfg.Modules.Revocation, "TRUSTMATE_ENABLE_REVOCATION")
	boolVar(&cfg.Modules.TSA, "TRUSTMATE_ENABLE_TSA")
	strVar(&cfg.Store.Driver, "TRUSTMATE_STORE_DRIVER")
	strVar(&cfg.Store.DSN, "TRUSTMATE_STORE_DSN")
	strVar(&cfg.Keystore.Dir, "TRUSTMATE_KEYSTORE_DIR")
	strVar(&cfg.Bootstrap.OutputDir, "TRUSTMATE_BOOTSTRAP_OUTPUT_DIR")
	strVar(&cfg.Profiles.Dir, "TRUSTMATE_PROFILES_DIR")
}

func validate(cfg Config) error {
	if cfg.Store.Driver != "sqlite" {
		return fmt.Errorf("config: unsupported store driver %q (only \"sqlite\" is supported)", cfg.Store.Driver)
	}
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
