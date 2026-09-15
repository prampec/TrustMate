// Package config loads TrustMate's configuration from defaults, an
// optional YAML file, and environment variable overrides, in that
// precedence order (env always wins), per docs/design.md's "container
// ready configuration" requirement.
package config

import "time"

// Config is the top-level, fully-resolved configuration.
type Config struct {
	// InstanceName identifies this deployment -- it seeds the Common Name
	// of every certificate generated at bootstrap (see RootCommonName
	// etc.) and is surfaced in startup logs, /healthz, /readyz, and the
	// trustmate_instance_info metric, so an operator running more than
	// one TrustMate instance (or replica set) can tell them apart.
	InstanceName string          `yaml:"instance_name"`
	Server       ServerConfig    `yaml:"server"`
	Log          LogConfig       `yaml:"log"`
	Modules      ModulesConfig   `yaml:"modules"`
	Store        StoreConfig     `yaml:"store"`
	Keystore     KeystoreConfig  `yaml:"keystore"`
	Bootstrap    BootstrapConfig `yaml:"bootstrap"`
	Profiles     ProfilesConfig  `yaml:"profiles"`
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
	// ACME enables RFC 8555 automated enrollment via External Account
	// Binding (see internal/acme, internal/api/acme.go, and
	// docs/design.md's Phase 5 roadmap entry). Off by default: it's an
	// additional certificate-issuance surface an operator opts into,
	// not something every deployment needs.
	ACME bool `yaml:"acme"`
}

type StoreConfig struct {
	// Driver is validated against the set of supported datastore backends:
	// "sqlite" (the default -- a single file, no separate service to run)
	// or "postgres" (a shared datastore multiple stateless API replicas
	// can point at, see docs/design.md's HA/clustering notes).
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

type KeystoreConfig struct {
	// Driver selects the KeyStore backend: "file" (the default -- an
	// encrypted file per key, see internal/keystore.FileKeyStore),
	// "vault" (HashiCorp Vault's Transit secrets engine, keys never
	// touching local disk -- see internal/keystore.VaultKeyStore), or
	// "pkcs11" (a PKCS#11 token/HSM -- see internal/keystore.PKCS11KeyStore;
	// only usable in a binary built with the "pkcs11" build tag, see
	// Dockerfile.pkcs11). All three are part of docs/design.md's Phase 5
	// roadmap entry.
	Driver string               `yaml:"driver"`
	Dir    string               `yaml:"dir"`
	Vault  VaultKeystoreConfig  `yaml:"vault"`
	PKCS11 PKCS11KeystoreConfig `yaml:"pkcs11"`
}

// VaultKeystoreConfig holds the non-secret Vault connection settings.
// The auth token is deliberately not a config field -- see
// keystore.LoadVaultToken, which resolves it the same out-of-band way
// LoadKEK resolves the file keystore's passphrase, so it never ends up
// alongside a logged configuration struct.
type VaultKeystoreConfig struct {
	Address      string `yaml:"address"`
	TransitMount string `yaml:"transit_mount"`
}

// PKCS11KeystoreConfig holds the non-secret PKCS#11 token connection
// settings. The PIN is deliberately not a config field -- see
// keystore.LoadPKCS11PIN, which resolves it the same out-of-band way
// LoadKEK resolves the file keystore's passphrase.
type PKCS11KeystoreConfig struct {
	// ModulePath is the path to the vendor's PKCS#11 .so, mounted into
	// the container at deploy time (see Dockerfile.pkcs11).
	ModulePath string `yaml:"module_path"`
	TokenLabel string `yaml:"token_label"`
	// SlotNumber, if non-nil, selects the token by slot instead of by
	// label -- crypto11.Config treats specifying both as an error, so
	// only one of TokenLabel/SlotNumber should be set.
	SlotNumber *int `yaml:"slot_number"`
}

// BootstrapConfig drives the first-run generation of the root CA,
// intermediate CA, admin access certificate, and server TLS certificate.
// Each certificate's Common Name is derived from Config.InstanceName (see
// Config.RootCommonName and its siblings below) rather than configured
// per-certificate here.
type BootstrapConfig struct {
	OutputDir            string        `yaml:"output_dir"`
	RootValidity         time.Duration `yaml:"root_validity"`
	IntermediateValidity time.Duration `yaml:"intermediate_validity"`
	AdminValidity        time.Duration `yaml:"admin_validity"`
	ServerValidity       time.Duration `yaml:"server_validity"`
	TSAValidity          time.Duration `yaml:"tsa_validity"`
}

type ProfilesConfig struct {
	// Dir, if set, is scanned for additional profile definitions beyond
	// the built-in defaults. Optional in Phase 0.
	Dir string `yaml:"dir"`
}

// RootCommonName, IntermediateCommonName, AdminCommonName,
// ServerCommonName, and TSACommonName are the Common Names bootstrap
// issues each first-run certificate under, each derived from
// InstanceName (e.g. InstanceName "TrustMate" gives "TrustMate Root
// CA"). There's no way to override one independently of the others --
// InstanceName is the single knob.
func (c Config) RootCommonName() string         { return c.InstanceName + " Root CA" }
func (c Config) IntermediateCommonName() string { return c.InstanceName + " Intermediate CA" }
func (c Config) AdminCommonName() string        { return c.InstanceName + " Admin Access" }
func (c Config) ServerCommonName() string       { return c.InstanceName + " REST API" }
func (c Config) TSACommonName() string          { return c.InstanceName + " TSA" }

// Defaults returns the baseline configuration before any file or
// environment overrides are applied.
func Defaults() Config {
	return Config{
		InstanceName: "TrustMate",
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
			Driver: "file",
			Dir:    "./data/keys",
		},
		Bootstrap: BootstrapConfig{
			OutputDir:            "./data/bootstrap",
			RootValidity:         10 * 365 * 24 * time.Hour,
			IntermediateValidity: 5 * 365 * 24 * time.Hour,
			AdminValidity:        365 * 24 * time.Hour,
			ServerValidity:       365 * 24 * time.Hour,
			TSAValidity:          2 * 365 * 24 * time.Hour,
		},
		Profiles: ProfilesConfig{},
	}
}
