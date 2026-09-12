package api

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/prampec/trustmate/internal/bootstrap"
	"github.com/prampec/trustmate/internal/config"
	"github.com/prampec/trustmate/internal/keystore"
	"github.com/prampec/trustmate/internal/revocation"
	"github.com/prampec/trustmate/internal/store/sqlite"
)

// newTestDeps bootstraps a full CA (root/intermediate/admin/server-tls)
// against a temp SQLite store and file keystore, then builds a Deps with
// a real IntermediateIssuer/CRLBuilder/OCSPResponder -- the same
// fixtures bootstrap_test.go uses, since only real, chain-verifiable
// material exercises these handlers meaningfully.
func newTestDeps(t *testing.T, mods ModuleConfig) Deps {
	t.Helper()

	st, err := sqlite.Open(filepath.Join(t.TempDir(), "trustmate.db"))
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	ks, err := keystore.NewFileKeyStore(filepath.Join(t.TempDir(), "keys"), []byte("test-passphrase"))
	if err != nil {
		t.Fatalf("NewFileKeyStore: %v", err)
	}

	cfg := config.Defaults()
	cfg.Bootstrap.OutputDir = filepath.Join(t.TempDir(), "bootstrap")
	cfg.Modules.Revocation = mods.EnableRevocation
	cfg.Modules.TSA = mods.EnableTSA

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := bootstrap.Run(context.Background(), logger, cfg, st, ks); err != nil {
		t.Fatalf("bootstrap.Run: %v", err)
	}

	issuer, err := bootstrap.LoadIntermediateIssuer(context.Background(), st, ks)
	if err != nil {
		t.Fatalf("LoadIntermediateIssuer: %v", err)
	}

	return Deps{
		Logger:             logger,
		Store:              st,
		IntermediateIssuer: issuer,
		PublicBaseURL:      cfg.Server.PublicBaseURL,
		ModuleConfig:       mods,
		CRLBuilder:         revocation.NewCRLBuilder(issuer),
		OCSPResponder:      revocation.NewOCSPResponder(issuer, st.Certificates()),
	}
}
