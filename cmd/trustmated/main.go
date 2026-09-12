// Command trustmated is the TrustMate service entrypoint: a self-contained
// CA + OCSP/CRL + RFC 3161 TSA REST service. See docs/design.md for the
// full design.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prampec/trustmate/internal/api"
	"github.com/prampec/trustmate/internal/bootstrap"
	"github.com/prampec/trustmate/internal/config"
	"github.com/prampec/trustmate/internal/keystore"
	"github.com/prampec/trustmate/internal/observability"
	"github.com/prampec/trustmate/internal/profiles"
	"github.com/prampec/trustmate/internal/revocation"
	"github.com/prampec/trustmate/internal/store/sqlite"
	"github.com/prampec/trustmate/internal/tsa"
)

func main() {
	cfg, err := config.LoadFromEnv(os.Getenv("TRUSTMATE_CONFIG_FILE"))
	if err != nil {
		os.Stderr.WriteString("trustmate: loading config: " + err.Error() + "\n")
		os.Exit(1)
	}

	logger := observability.NewLogger(os.Stdout, cfg.Log.Level)

	db, err := sqlite.Open(cfg.Store.DSN)
	if err != nil {
		logger.Error("opening datastore failed", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	kek, err := keystore.LoadKEK()
	if err != nil {
		logger.Error("loading keystore passphrase failed", "err", err)
		os.Exit(1)
	}
	ks, err := keystore.NewFileKeyStore(cfg.Keystore.Dir, kek)
	if err != nil {
		logger.Error("opening keystore failed", "err", err)
		os.Exit(1)
	}

	bootCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	_, err = bootstrap.Run(bootCtx, logger, cfg, db, ks)
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

	mods := api.ModuleConfig{
		EnableRevocation: cfg.Modules.Revocation,
		EnableTSA:        cfg.Modules.TSA,
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
	metrics := observability.NewMetrics()
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
		IntermediateIssuer: interIssuer,
		PublicBaseURL:      cfg.Server.PublicBaseURL,
		KeyStore:           ks,
		TSACommonName:      cfg.Bootstrap.TSACommonName,
		TSAValidity:        cfg.Bootstrap.TSAValidity,
		ModuleConfig:       mods,
		Profiles:           profileRegistry,
		Metrics:            metrics,
		CRLBuilder:         revocation.NewCRLBuilder(interIssuer, db.Certificates()),
		OCSPResponder:      revocation.NewOCSPResponder(interIssuer, db.Certificates()),
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
		logger.Info("listening", "addr", cfg.Server.ListenAddr, "revocation", mods.EnableRevocation, "tsa", mods.EnableTSA)
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
