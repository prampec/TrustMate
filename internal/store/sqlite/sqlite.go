// Package sqlite is the SQLite implementation of store.Store, the v1
// datastore default per docs/design.md (single file, trivially backed up,
// trivially mounted into a container volume). The driver
// (modernc.org/sqlite) is pure Go -- required because the project's
// Dockerfile builds with CGO_ENABLED=0 into a scratch image.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/prampec/trustmate/internal/store"
)

// SQLiteStore implements store.Store.
type SQLiteStore struct {
	db *sql.DB
}

// Open opens (creating if necessary) a SQLite database at dsn and
// applies any pending migrations.
func Open(dsn string) (*SQLiteStore, error) {
	if dir := filepath.Dir(dsn); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("sqlite: creating dir for %s: %w", dsn, err)
		}
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: opening %s: %w", dsn, err)
	}
	// SQLite only supports one writer at a time; serialize to avoid
	// SQLITE_BUSY under the single-process API server.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: enabling foreign keys: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}

	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func (s *SQLiteStore) Certificates() store.CertificateRepository {
	return certificateRepository{db: s.db}
}

func (s *SQLiteStore) Profiles() store.ProfileRepository {
	return profileRepository{db: s.db}
}

func (s *SQLiteStore) Audit() store.AuditRepository {
	return auditRepository{db: s.db}
}
