package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/prampec/trustmate/internal/store"
)

type auditRepository struct {
	db *sql.DB
}

func (r auditRepository) Append(ctx context.Context, entry store.AuditEntry) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO audit_log (ts, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)`,
		entry.Timestamp.UTC().Format(time.RFC3339), entry.Actor, entry.Action, entry.Target, entry.Detail)
	if err != nil {
		return fmt.Errorf("sqlite: appending audit entry: %w", err)
	}
	return nil
}

func (r auditRepository) List(ctx context.Context, limit int) ([]store.AuditEntry, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, ts, actor, action, target, detail FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("sqlite: listing audit entries: %w", err)
	}
	defer rows.Close()

	var out []store.AuditEntry
	for rows.Next() {
		var (
			e      store.AuditEntry
			ts     string
			target sql.NullString
			detail sql.NullString
		)
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &target, &detail); err != nil {
			return nil, fmt.Errorf("sqlite: scanning audit entry: %w", err)
		}
		if e.Timestamp, err = time.Parse(time.RFC3339, ts); err != nil {
			return nil, fmt.Errorf("sqlite: parsing ts: %w", err)
		}
		e.Target = target.String
		e.Detail = detail.String
		out = append(out, e)
	}
	return out, rows.Err()
}
