// Package postgres is the Postgres implementation of store.Store,
// selected via store.driver: postgres (SQLite remains the default -- see
// internal/store/sqlite). It exists so a horizontally-scaled deployment
// can point multiple stateless API instances at a shared datastore
// without an API rewrite, per docs/design.md's Phase 4/5 roadmap. The
// driver (jackc/pgx/v5, in database/sql stdlib mode) is pure Go --
// required because the project's Dockerfile builds with CGO_ENABLED=0
// into a scratch image.
package postgres

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/prampec/trustmate/internal/store"
)

// PostgresStore implements store.Store.
type PostgresStore struct {
	db *sql.DB
}

// Open opens a Postgres database at dsn and applies any pending
// migrations. Unlike sqlite.Open, connections are pooled: Postgres
// supports concurrent writers, so nothing here forces single-connection
// serialization the way SQLite's SetMaxOpenConns(1) does.
func Open(dsn string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: opening %s: %w", dsn, err)
	}
	db.SetMaxOpenConns(25)

	if err := runMigrations(db); err != nil {
		db.Close()
		return nil, err
	}

	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *PostgresStore) Close() error {
	return s.db.Close()
}

func (s *PostgresStore) Certificates() store.CertificateRepository {
	return certificateRepository{db: s.db}
}

func (s *PostgresStore) Profiles() store.ProfileRepository {
	return profileRepository{db: s.db}
}

func (s *PostgresStore) Audit() store.AuditRepository {
	return auditRepository{db: s.db}
}

func (s *PostgresStore) ClientRoles() store.ClientRoleRepository {
	return clientRoleRepository{db: s.db}
}

func (s *PostgresStore) ACMEEABTokens() store.ACMEEABTokenRepository {
	return acmeEABTokenRepository{db: s.db}
}

func (s *PostgresStore) ACMEAccounts() store.ACMEAccountRepository {
	return acmeAccountRepository{db: s.db}
}

func (s *PostgresStore) ACMEOrders() store.ACMEOrderRepository {
	return acmeOrderRepository{db: s.db}
}

func (s *PostgresStore) ACMENonces() store.ACMENonceRepository {
	return acmeNonceRepository{db: s.db}
}

// WithExclusiveLock backs store.Store's method with a session-level
// Postgres advisory lock -- see WithAdvisoryLock.
func (s *PostgresStore) WithExclusiveLock(ctx context.Context, key int64, fn func() error) error {
	return WithAdvisoryLock(ctx, s.db, key, fn)
}

// DB exposes the underlying *sql.DB for callers that need a raw
// connection -- e.g. internal/bootstrap's Postgres advisory lock around
// first-run CA generation, which has to run outside any repository
// interface. Not part of store.Store; callers must type-assert to
// *PostgresStore to reach it.
func (s *PostgresStore) DB() *sql.DB {
	return s.db
}
