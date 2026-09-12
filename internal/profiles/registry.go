package profiles

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/prampec/trustmate/internal/keystore"
	"github.com/prampec/trustmate/internal/store"
)

// Registry is the runtime lookup source for certificate profiles: the
// compiled-in built-ins (see All()) plus any additional profiles loaded
// from a config directory, backed by the store's versioned profiles
// table. See docs/design.md's Phase 3 roadmap entry ("profile config,
// multiple profiles, not hardcoded").
type Registry struct {
	repo store.ProfileRepository
	dir  string

	mu       sync.RWMutex
	profiles map[string]Profile
	builtins map[string]bool
}

// NewRegistry seeds a Registry with the built-in profiles and, if dir is
// non-empty, loads additional profile definitions from it. A load error
// is returned rather than silently ignored -- a misconfigured profile
// directory should fail startup, not run with a partially-loaded set.
func NewRegistry(ctx context.Context, repo store.ProfileRepository, dir string) (*Registry, error) {
	r := &Registry{
		repo:     repo,
		dir:      dir,
		profiles: map[string]Profile{},
		builtins: map[string]bool{},
	}
	for _, p := range All() {
		r.profiles[p.Name] = p
		r.builtins[p.Name] = true
	}
	if err := r.Load(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// Lookup finds a profile by name, built-in or config-loaded.
func (r *Registry) Lookup(name string) (Profile, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.profiles[name]
	return p, ok
}

// All returns every currently loaded profile (built-in and config-loaded).
func (r *Registry) All() []Profile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Profile, 0, len(r.profiles))
	for _, p := range r.profiles {
		out = append(out, p)
	}
	return out
}

// Load (re-)scans r.dir for *.yaml/*.yml profile definitions, validates
// and versions each against the profiles store table, and swaps them
// into the in-memory map alongside the (untouched) built-ins. A no-op if
// dir is empty. Called once at startup and again by POST
// /v1/profiles/reload.
func (r *Registry) Load(ctx context.Context) error {
	if r.dir == "" {
		return nil
	}
	matches, err := filepath.Glob(filepath.Join(r.dir, "*.yaml"))
	if err != nil {
		return fmt.Errorf("profiles: globbing %s/*.yaml: %w", r.dir, err)
	}
	ymlMatches, err := filepath.Glob(filepath.Join(r.dir, "*.yml"))
	if err != nil {
		return fmt.Errorf("profiles: globbing %s/*.yml: %w", r.dir, err)
	}
	matches = append(matches, ymlMatches...)

	loaded := map[string]Profile{}
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("profiles: reading %s: %w", path, err)
		}
		var cfg profileConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("profiles: parsing %s: %w", path, err)
		}
		p, err := cfg.toProfile()
		if err != nil {
			return fmt.Errorf("profiles: %s: %w", path, err)
		}
		if r.builtins[p.Name] {
			return fmt.Errorf("profiles: %s: profile name %q collides with a built-in profile", path, p.Name)
		}
		if _, dup := loaded[p.Name]; dup {
			return fmt.Errorf("profiles: duplicate profile name %q across config files", p.Name)
		}
		loaded[p.Name] = p
	}

	for name, p := range loaded {
		versioned, err := r.upsertVersioned(ctx, p)
		if err != nil {
			return err
		}
		loaded[name] = versioned
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for name := range r.profiles {
		if !r.builtins[name] {
			delete(r.profiles, name)
		}
	}
	for name, p := range loaded {
		r.profiles[name] = p
	}
	return nil
}

// upsertVersioned stores p in the profiles table, bumping the version
// only when its serialized content differs from the last stored version
// -- so reloading an unchanged file doesn't spin the version number. It
// returns p with Version set to whatever was actually stored, since the
// caller's copy (passed by value) doesn't see mutations made here.
func (r *Registry) upsertVersioned(ctx context.Context, p Profile) (Profile, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return Profile{}, fmt.Errorf("profiles: encoding profile %s: %w", p.Name, err)
	}

	version := 1
	prev, err := r.repo.Get(ctx, p.Name)
	if err == nil {
		version = prev.Version
		if string(prev.Data) != string(data) {
			version = prev.Version + 1
		}
	} else if err != store.ErrNotFound {
		return Profile{}, fmt.Errorf("profiles: loading previous version of %s: %w", p.Name, err)
	}

	p.Version = version
	data, err = json.Marshal(p)
	if err != nil {
		return Profile{}, fmt.Errorf("profiles: encoding profile %s: %w", p.Name, err)
	}
	if err := r.repo.Upsert(ctx, store.ProfileRecord{
		Name:      p.Name,
		Version:   version,
		Data:      data,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		return Profile{}, fmt.Errorf("profiles: persisting profile %s: %w", p.Name, err)
	}
	return p, nil
}

// profileConfig is the YAML-facing DTO for a config-defined profile --
// string-based so the file format doesn't need to know Go's x509/keystore
// constant encodings. toProfile validates every enum string.
type profileConfig struct {
	Name         string   `yaml:"name"`
	KeyAlgorithm string   `yaml:"key_algorithm"`
	KeyUsage     []string `yaml:"key_usage"`
	ExtKeyUsage  []string `yaml:"ext_key_usage"`
	CriticalEKU  bool     `yaml:"critical_eku"`
	Validity     string   `yaml:"validity"`
	EnableOCSP   bool     `yaml:"enable_ocsp"`
	EnableCRL    bool     `yaml:"enable_crl"`
}

var keyAlgorithms = map[string]keystore.Algorithm{
	"ecdsa-p256": keystore.AlgorithmECDSAP256,
	"rsa-2048":   keystore.AlgorithmRSA2048,
}

var keyUsageBits = map[string]x509.KeyUsage{
	"digitalSignature":  x509.KeyUsageDigitalSignature,
	"contentCommitment": x509.KeyUsageContentCommitment,
	"keyEncipherment":   x509.KeyUsageKeyEncipherment,
	"dataEncipherment":  x509.KeyUsageDataEncipherment,
	"keyAgreement":      x509.KeyUsageKeyAgreement,
	"certSign":          x509.KeyUsageCertSign,
	"crlSign":           x509.KeyUsageCRLSign,
	"encipherOnly":      x509.KeyUsageEncipherOnly,
	"decipherOnly":      x509.KeyUsageDecipherOnly,
}

var extKeyUsages = map[string]x509.ExtKeyUsage{
	"serverAuth":      x509.ExtKeyUsageServerAuth,
	"clientAuth":      x509.ExtKeyUsageClientAuth,
	"codeSigning":     x509.ExtKeyUsageCodeSigning,
	"emailProtection": x509.ExtKeyUsageEmailProtection,
	"timeStamping":    x509.ExtKeyUsageTimeStamping,
	"ocspSigning":     x509.ExtKeyUsageOCSPSigning,
}

func (c profileConfig) toProfile() (Profile, error) {
	if c.Name == "" {
		return Profile{}, fmt.Errorf("profile name is required")
	}
	alg, ok := keyAlgorithms[c.KeyAlgorithm]
	if !ok {
		return Profile{}, fmt.Errorf("profile %s: unknown key_algorithm %q", c.Name, c.KeyAlgorithm)
	}
	var usage x509.KeyUsage
	for _, s := range c.KeyUsage {
		bit, ok := keyUsageBits[s]
		if !ok {
			return Profile{}, fmt.Errorf("profile %s: unknown key_usage %q", c.Name, s)
		}
		usage |= bit
	}
	ekus := make([]x509.ExtKeyUsage, 0, len(c.ExtKeyUsage))
	for _, s := range c.ExtKeyUsage {
		eku, ok := extKeyUsages[s]
		if !ok {
			return Profile{}, fmt.Errorf("profile %s: unknown ext_key_usage %q", c.Name, s)
		}
		ekus = append(ekus, eku)
	}
	validity, err := time.ParseDuration(c.Validity)
	if err != nil {
		return Profile{}, fmt.Errorf("profile %s: invalid validity %q: %w", c.Name, c.Validity, err)
	}

	return Profile{
		Name:         c.Name,
		Version:      1,
		KeyAlgorithm: alg,
		KeyUsage:     usage,
		ExtKeyUsage:  ekus,
		CriticalEKU:  c.CriticalEKU,
		Validity:     validity,
		EnableOCSP:   c.EnableOCSP,
		EnableCRL:    c.EnableCRL,
	}, nil
}
