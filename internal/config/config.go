// Package config loads TrustMate's configuration from defaults, an
// optional YAML file, and environment variable overrides, in that
// precedence order (env always wins), per docs/design.md's "container
// ready configuration" requirement.
package config

import "time"

// Config is the top-level, fully-resolved configuration.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Log       LogConfig       `yaml:"log"`
	Modules   ModulesConfig   `yaml:"modules"`
	Store     StoreConfig     `yaml:"store"`
	Keystore  KeystoreConfig  `yaml:"keystore"`
	Bootstrap BootstrapConfig `yaml:"bootstrap"`
	Profiles  ProfilesConfig  `yaml:"profiles"`
}

type ServerConfig struct {
	ListenAddr string   `yaml:"listen_addr"`
	TLSSANs    []string `yaml:"tls_sans"`
	// PublicBaseURL is this deployment's externally reachable origin
	// (scheme+host), templated into AIA/CDP/OCSP certificate extensions
	// at issuance time so those pointers are real, dereferenceable URIs.
	PublicBaseURL string `yaml:"public_base_url"`
}

type LogConfig struct {
	Level string `yaml:"level"`
}

// ModulesConfig controls which optional route groups (and, at bootstrap,
// which certificate extensions) are enabled. The pki core is always on.
type ModulesConfig struct {
	Revocation bool `yaml:"revocation"`
	TSA        bool `yaml:"tsa"`
}

type StoreConfig struct {
	// Driver is validated against the set of supported datastore backends.
	// Only "sqlite" is supported in Phase 0.
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

type KeystoreConfig struct {
	Dir string `yaml:"dir"`
}

// BootstrapConfig drives the first-run generation of the root CA,
// intermediate CA, admin access certificate, and server TLS certificate.
type BootstrapConfig struct {
	OutputDir              string        `yaml:"output_dir"`
	RootCommonName         string        `yaml:"root_cn"`
	IntermediateCommonName string        `yaml:"intermediate_cn"`
	AdminCommonName        string        `yaml:"admin_cn"`
	ServerCommonName       string        `yaml:"server_cn"`
	TSACommonName          string        `yaml:"tsa_cn"`
	RootValidity           time.Duration `yaml:"root_validity"`
	IntermediateValidity   time.Duration `yaml:"intermediate_validity"`
	AdminValidity          time.Duration `yaml:"admin_validity"`
	ServerValidity         time.Duration `yaml:"server_validity"`
	TSAValidity            time.Duration `yaml:"tsa_validity"`
}

type ProfilesConfig struct {
	// Dir, if set, is scanned for additional profile definitions beyond
	// the built-in defaults. Optional in Phase 0.
	Dir string `yaml:"dir"`
}

// Defaults returns the baseline configuration before any file or
// environment overrides are applied.
func Defaults() Config {
	return Config{
		Server: ServerConfig{
			ListenAddr:    ":8080",
			TLSSANs:       []string{"localhost"},
			PublicBaseURL: "https://localhost:8080",
		},
		Log: LogConfig{
			Level: "INFO",
		},
		Modules: ModulesConfig{
			Revocation: true,
			TSA:        true,
		},
		Store: StoreConfig{
			Driver: "sqlite",
			DSN:    "./data/trustmate.db",
		},
		Keystore: KeystoreConfig{
			Dir: "./data/keys",
		},
		Bootstrap: BootstrapConfig{
			OutputDir:              "./data/bootstrap",
			RootCommonName:         "TrustMate Root CA",
			IntermediateCommonName: "TrustMate Intermediate CA",
			AdminCommonName:        "TrustMate Admin Access",
			ServerCommonName:       "TrustMate REST API",
			TSACommonName:          "TrustMate TSA",
			RootValidity:           10 * 365 * 24 * time.Hour,
			IntermediateValidity:   5 * 365 * 24 * time.Hour,
			AdminValidity:          365 * 24 * time.Hour,
			ServerValidity:         365 * 24 * time.Hour,
			TSAValidity:            2 * 365 * 24 * time.Hour,
		},
		Profiles: ProfilesConfig{},
	}
}
