// Package migrate is the shared schema-migration runner for
// internal/store/sqlite and internal/store/postgres: both backends embed
// the same "read a directory of NNNN_name.sql files, apply the ones
// missing from schema_migrations, each in its own transaction" algorithm
// -- factored out here so the two implementations can't silently drift,
// parameterized only by the small handful of things that actually differ
// between the two SQL dialects (see Dialect).
package migrate

import (
	"database/sql"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

// Dialect captures the SQL differences between backends that Run needs:
// the DDL for the schema_migrations ledger table itself (SQLite's TEXT
// vs Postgres's native TIMESTAMPTZ for applied_at), the bound-parameter
// placeholder syntax (SQLite's positional "?" vs Postgres's numbered
// "$1", "$2", ...), and how "now" is passed as that bound parameter.
type Dialect struct {
	CreateSchemaTable string
	Placeholder       func(n int) string
	Now               func() any
}

// Run applies every migration embedded in fsys under dir that hasn't
// been recorded in schema_migrations yet, in filename ("NNNN_name.sql")
// order, each inside its own transaction. It is idempotent: reapplying
// against an already-migrated database is a no-op.
func Run(db *sql.DB, fsys fs.FS, dir string, d Dialect) error {
	if _, err := db.Exec(d.CreateSchemaTable); err != nil {
		return fmt.Errorf("migrate: creating schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return fmt.Errorf("migrate: reading embedded migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		version, err := parseVersion(name)
		if err != nil {
			return err
		}

		var count int
		checkQuery := fmt.Sprintf(`SELECT COUNT(1) FROM schema_migrations WHERE version = %s`, d.Placeholder(1))
		if err := db.QueryRow(checkQuery, version).Scan(&count); err != nil {
			return fmt.Errorf("migrate: checking migration %d: %w", version, err)
		}
		if count > 0 {
			continue
		}

		sqlBytes, err := fs.ReadFile(fsys, dir+"/"+name)
		if err != nil {
			return fmt.Errorf("migrate: reading migration %s: %w", name, err)
		}

		if err := apply(db, d, version, string(sqlBytes)); err != nil {
			return fmt.Errorf("migrate: applying migration %s: %w", name, err)
		}
	}
	return nil
}

func apply(db *sql.DB, d Dialect, version int, script string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(script); err != nil {
		return err
	}
	insert := fmt.Sprintf(`INSERT INTO schema_migrations (version, applied_at) VALUES (%s, %s)`, d.Placeholder(1), d.Placeholder(2))
	if _, err := tx.Exec(insert, version, d.Now()); err != nil {
		return err
	}
	return tx.Commit()
}

func parseVersion(name string) (int, error) {
	prefix, _, ok := strings.Cut(name, "_")
	if !ok {
		return 0, fmt.Errorf("migrate: migration filename %q missing version prefix", name)
	}
	version, err := strconv.Atoi(prefix)
	if err != nil {
		return 0, fmt.Errorf("migrate: migration filename %q has non-numeric version: %w", name, err)
	}
	return version, nil
}
