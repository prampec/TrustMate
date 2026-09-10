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
	"strconv"
	"syscall"
	"time"

	"github.com/prampec/trustmate/internal/api"
	"github.com/prampec/trustmate/internal/observability"
)

func main() {
	logger := observability.NewLogger(os.Stdout, getenv("TRUSTMATE_LOG_LEVEL", "INFO"))

	mods := api.ModuleConfig{
		EnableRevocation: getenvBool("TRUSTMATE_ENABLE_REVOCATION", true),
		EnableTSA:        getenvBool("TRUSTMATE_ENABLE_TSA", true),
	}

	router := api.NewRouter(logger, mods, nil /* TODO: wire datastore ping once store module exists */)

	addr := getenv("TRUSTMATE_LISTEN_ADDR", ":8080")
	server := &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("listening", "addr", addr, "revocation", mods.EnableRevocation, "tsa", mods.EnableTSA)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
}

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func getenvBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}
