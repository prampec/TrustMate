package bootstrap

import (
	"context"
	"crypto/tls"
	"path/filepath"
	"testing"

	"github.com/prampec/trustmate/internal/config"
)

func TestLoadServerTLSConfigAllowsOptionalVerifiedClientCerts(t *testing.T) {
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Bootstrap.OutputDir = filepath.Join(t.TempDir(), "bootstrap")
	st := newTestStore(t)
	ks := newTestKeyStore(t)

	if _, err := Run(ctx, discardLogger(), cfg, st, ks); err != nil {
		t.Fatalf("Run: %v", err)
	}

	tlsConfig, err := LoadServerTLSConfig(ctx, st, ks)
	if err != nil {
		t.Fatalf("LoadServerTLSConfig: %v", err)
	}
	if tlsConfig.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("ClientAuth = %v, want VerifyClientCertIfGiven", tlsConfig.ClientAuth)
	}
	if tlsConfig.ClientCAs == nil {
		t.Fatal("ClientCAs is nil, want a pool containing root+intermediate")
	}
	if len(tlsConfig.ClientCAs.Subjects()) == 0 { //nolint:staticcheck // deprecated but fine for this sanity check
		t.Error("ClientCAs pool is empty, want root and intermediate certificates")
	}
}
