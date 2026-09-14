package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/prampec/trustmate/internal/store/storetest"
)

func openTest(t *testing.T) *SQLiteStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trustmate.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpenAndPing(t *testing.T) {
	db := openTest(t)
	if err := db.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trustmate.db")
	db1, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	db1.Close()

	db2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open (reapplying migrations): %v", err)
	}
	defer db2.Close()
	if err := db2.Ping(context.Background()); err != nil {
		t.Fatalf("Ping after reopen: %v", err)
	}
}

// TestStoreContract runs the shared store.Store behavioral suite --
// internal/store/postgres runs the identical suite, so the two backends
// can't silently drift in behavior.
func TestStoreContract(t *testing.T) {
	storetest.Run(t, openTest(t))
}
