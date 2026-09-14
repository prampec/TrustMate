package postgres

import (
	"context"
	"database/sql"
	"fmt"
)

// BootstrapLockKey is the fixed pg_advisory_lock key cmd/trustmated uses
// to serialize first-run CA bootstrap across replicas when
// store.driver is postgres. internal/bootstrap.Run's "does a root cert
// already exist" check-then-act is a classic race if two replicas start
// simultaneously against a fresh, empty database -- both would see no
// root cert and both would generate one. SQLite deployments don't need
// this: SQLite is single-process by construction (see Open's
// SetMaxOpenConns(1) in internal/store/sqlite/sqlite.go), so there's
// only ever one replica to race with itself.
const BootstrapLockKey = 0x54727374 // arbitrary but stable ("Trst" in hex)

// WithAdvisoryLock runs fn while holding a session-level Postgres
// advisory lock on key, blocking until it's acquired (or ctx is done).
// The lock is scoped to one dedicated connection, explicitly unlocked
// (not just released by connection close) so it lets go promptly rather
// than lingering until the pool decides to recycle that connection.
func WithAdvisoryLock(ctx context.Context, db *sql.DB, key int64, fn func() error) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("postgres: acquiring connection for advisory lock: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, key); err != nil {
		return fmt.Errorf("postgres: acquiring advisory lock: %w", err)
	}
	defer func() {
		if _, err := conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, key); err != nil {
			// Best-effort: the connection is about to be closed anyway
			// (see the Close deferred above), which also releases the
			// lock -- just later than an explicit unlock would.
			_ = err
		}
	}()

	return fn()
}
