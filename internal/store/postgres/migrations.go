package postgres

import (
	"database/sql"
	"embed"
	"fmt"
	"time"

	dbmigrate "github.com/prampec/trustmate/internal/store/migrate"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

var postgresDialect = dbmigrate.Dialect{
	CreateSchemaTable: `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL
	)`,
	Placeholder: func(n int) string { return fmt.Sprintf("$%d", n) },
	Now:         func() any { return time.Now().UTC() },
}

// runMigrations applies every embedded migration that hasn't been
// recorded in schema_migrations yet -- see internal/store/migrate.Run's
// doc comment. Only postgresDialect ("$N" placeholders, a native
// TIMESTAMPTZ applied_at column) differs from internal/store/sqlite's
// runMigrations.
func runMigrations(db *sql.DB) error {
	return dbmigrate.Run(db, migrationsFS, "migrations", postgresDialect)
}
