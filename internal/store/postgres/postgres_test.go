package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/prampec/trustmate/internal/store/storetest"
)

// openTest connects to the Postgres instance named by
// TRUSTMATE_PG_TEST_DSN, skipping the test cleanly when it's unset --
// there's no way to spin up a throwaway Postgres locally the way
// sqlite's openTest uses a t.TempDir() file, and this sandbox doesn't
// have Docker available. CI sets the env var against a postgres:16
// service container (see .github/workflows/ci.yml) for real coverage.
func openTest(t *testing.T) *PostgresStore {
	t.Helper()
	dsn := os.Getenv("TRUSTMATE_PG_TEST_DSN")
	if dsn == "" {
		t.Skip("TRUSTMATE_PG_TEST_DSN not set; skipping Postgres-backed test")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// The suite uses fixed literal identifiers (see storetest), so start
	// from a clean slate against what may be a long-lived test database.
	if _, err := db.db.Exec(`TRUNCATE client_roles, certificates, profiles, audit_log RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncating test tables: %v", err)
	}
	return db
}

func TestOpenAndPing(t *testing.T) {
	db := openTest(t)
	if err := db.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	dsn := os.Getenv("TRUSTMATE_PG_TEST_DSN")
	if dsn == "" {
		t.Skip("TRUSTMATE_PG_TEST_DSN not set; skipping Postgres-backed test")
	}
	db1, err := Open(dsn)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	db1.Close()

	db2, err := Open(dsn)
	if err != nil {
		t.Fatalf("second Open (reapplying migrations): %v", err)
	}
	defer db2.Close()
	if err := db2.Ping(context.Background()); err != nil {
		t.Fatalf("Ping after reopen: %v", err)
	}
}

// TestStoreContract runs the shared store.Store behavioral suite --
// internal/store/sqlite runs the identical suite, so the two backends
// can't silently drift in behavior.
func TestStoreContract(t *testing.T) {
	storetest.Run(t, openTest(t))
}
