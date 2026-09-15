// Command trustmated is the TrustMate service entrypoint: a self-contained
// CA + OCSP/CRL + RFC 3161 TSA REST service. See docs/design.md for the
// full design.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prampec/trustmate/internal/api"
	"github.com/prampec/trustmate/internal/bootstrap"
	"github.com/prampec/trustmate/internal/config"
	"github.com/prampec/trustmate/internal/keystore"
	"github.com/prampec/trustmate/internal/observability"
	"github.com/prampec/trustmate/internal/pki"
	"github.com/prampec/trustmate/internal/profiles"
	"github.com/prampec/trustmate/internal/revocation"
	"github.com/prampec/trustmate/internal/store"
	"github.com/prampec/trustmate/internal/store/postgres"
	"github.com/prampec/trustmate/internal/store/sqlite"
	"github.com/prampec/trustmate/internal/tsa"
	"github.com/prampec/trustmate/internal/version"
)

// openStore constructs the store.Store backend named by cfg.Driver.
// config.validate() already restricts Driver to a known value, so the
// default case here is unreachable in practice -- it's a safety net, not
// expected user-facing behavior.
func openStore(cfg config.StoreConfig) (store.Store, error) {
	switch cfg.Driver {
	case "postgres":
		return postgres.Open(cfg.DSN)
	default:
		return sqlite.Open(cfg.DSN)
	}
}

// openKeyStore constructs the keystore.KeyStore backend named by
// cfg.Driver. config.validate() already restricts Driver to a known
// value, so the default case here is unreachable in practice -- it's a
// safety net, not expected user-facing behavior.
func openKeyStore(cfg config.KeystoreConfig) (keystore.KeyStore, error) {
	switch cfg.Driver {
	case "vault":
		token, err := keystore.LoadVaultToken()
		if err != nil {
			return nil, err
		}
		return keystore.NewVaultKeyStore(keystore.VaultConfig{
			Address:      cfg.Vault.Address,
			TransitMount: cfg.Vault.TransitMount,
		}, token)
	case "pkcs11":
		return newPKCS11KeyStore(cfg.PKCS11)
	default:
		kek, err := keystore.LoadKEK()
		if err != nil {
			return nil, err
		}
		return keystore.NewFileKeyStore(cfg.Dir, kek)
	}
}

// runBootstrap calls bootstrap.Run through db.WithExclusiveLock, so
// first-run CA generation is serialized across replicas on backends
// where that's possible (Postgres, via a session-level advisory lock --
// see postgres.BootstrapLockKey's doc comment for why: HA/clustering,
// multiple replicas racing on first boot against a shared, empty
// database). SQLite's WithExclusiveLock is a no-op call-through: it's
// single-process by construction, so there's only ever one replica to
// race with itself.
func runBootstrap(ctx context.Context, logger *slog.Logger, cfg config.Config, db store.Store, ks keystore.KeyStore) error {
	return db.WithExclusiveLock(ctx, postgres.BootstrapLockKey, func() error {
		_, err := bootstrap.Run(ctx, logger, cfg, db, ks)
		return err
	})
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-version") {
		os.Stdout.WriteString("trustmated " + version.Version + "\n")
		return
	}

	cfg, err := config.LoadFromEnv(os.Getenv("TRUSTMATE_CONFIG_FILE"))
	if err != nil {
		os.Stderr.WriteString("trustmate: loading config: " + err.Error() + "\n")
		os.Exit(1)
	}

	logger := observability.NewLogger(os.Stdout, cfg.Log.Level)
	logger.Info("trustmate starting", "instance", cfg.InstanceName)

	// openStore and openKeyStore are independent I/O (a store connection
	// plus migrations vs. a Vault/PKCS11/file keystore open, each
	// potentially a real network or HSM round trip) -- run them
	// concurrently so startup latency is roughly max(storeOpenTime,
	// keystoreOpenTime) rather than their sum.
	var (
		db    store.Store
		ks    keystore.KeyStore
		dbErr error
		ksErr error
		wg    sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		db, dbErr = openStore(cfg.Store)
	}()
	go func() {
		defer wg.Done()
		ks, ksErr = openKeyStore(cfg.Keystore)
	}()
	wg.Wait()
	if dbErr != nil {
		logger.Error("opening datastore failed", "err", dbErr)
		os.Exit(1)
	}
	defer db.Close()
	if ksErr != nil {
		logger.Error("opening keystore failed", "err", ksErr)
		os.Exit(1)
	}
	// Only PKCS11KeyStore needs closing (it holds a PKCS#11 session
	// pool); FileKeyStore and VaultKeyStore don't implement Close, so
	// this type assertion is a no-op for them rather than requiring a
	// no-op method on every backend.
	if closer, ok := ks.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	bootCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = runBootstrap(bootCtx, logger, cfg, db, ks)
	cancel()
	if err != nil {
		logger.Error("bootstrap failed", "err", err)
		os.Exit(1)
	}

	tlsCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	tlsConfig, err := bootstrap.LoadServerTLSConfig(tlsCtx, db, ks)
	cancel()
	if err != nil {
		logger.Error("loading server TLS configuration failed", "err", err)
		os.Exit(1)
	}

	interCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	interIssuer, err := bootstrap.LoadIntermediateIssuer(interCtx, db, ks)
	cancel()
	if err != nil {
		logger.Error("loading intermediate CA issuer failed", "err", err)
		os.Exit(1)
	}

	rootCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	rootIssuer, err := bootstrap.LoadRootIssuer(rootCtx, db, ks)
	cancel()
	if err != nil {
		logger.Error("loading root CA issuer failed", "err", err)
		os.Exit(1)
	}

	mods := api.ModuleConfig{
		EnableRevocation: cfg.Modules.Revocation,
		EnableTSA:        cfg.Modules.TSA,
		EnableACME:       cfg.Modules.ACME,
	}

	var tsaResponder *tsa.Responder
	if mods.EnableTSA {
		tsaCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		tsaIssuer, err := bootstrap.LoadTSAIssuer(tsaCtx, db, ks)
		cancel()
		if err != nil {
			logger.Error("loading TSA issuer failed", "err", err)
			os.Exit(1)
		}
		tsaResponder = tsa.NewResponder(tsaIssuer, interIssuer.Cert)
	}
	metrics := observability.NewMetrics(cfg.InstanceName)
	ready := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := db.Ping(ctx)
		if err == nil {
			metrics.StoreUp.Set(1)
		} else {
			metrics.StoreUp.Set(0)
		}
		return err
	}

	profileCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	profileRegistry, err := profiles.NewRegistry(profileCtx, db.Profiles(), cfg.Profiles.Dir)
	cancel()
	if err != nil {
		logger.Error("loading profile registry failed", "err", err)
		os.Exit(1)
	}

	router := api.NewRouter(api.Deps{
		Logger:             logger,
		Store:              db,
		InstanceName:       cfg.InstanceName,
		IntermediateIssuer: interIssuer,
		PublicBaseURL:      cfg.Server.PublicBaseURL,
		KeyStore:           ks,
		TSACommonName:      cfg.TSACommonName(),
		TSAValidity:        cfg.Bootstrap.TSAValidity,
		ModuleConfig:       mods,
		Profiles:           profileRegistry,
		Metrics:            metrics,
		CRLBuilder:         revocation.NewCRLBuilder(interIssuer, db.Certificates()),
		RootCRLBuilder:     revocation.NewCRLBuilder(rootIssuer, db.Certificates()),
		OCSPResponder:      revocation.NewOCSPResponder([]pki.Issuer{rootIssuer, interIssuer}, db.Certificates()),
		TSAResponder:       tsaResponder,
	}, ready)

	server := &http.Server{
		Addr:              cfg.Server.ListenAddr,
		Handler:           router,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("listening", "instance", cfg.InstanceName, "addr", cfg.Server.ListenAddr, "revocation", mods.EnableRevocation, "tsa", mods.EnableTSA)
		if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
}
