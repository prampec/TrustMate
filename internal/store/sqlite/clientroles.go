package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/prampec/trustmate/internal/store"
)

type clientRoleRepository struct {
	db *sql.DB
}

func (r clientRoleRepository) Assign(ctx context.Context, rec store.ClientRoleRecord) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO client_roles (cert_serial, role, created_at) VALUES (?, ?, ?)
		ON CONFLICT (cert_serial) DO UPDATE SET role = excluded.role`,
		rec.CertSerial, string(rec.Role), rec.CreatedAt.UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("sqlite: assigning role to certificate %s: %w", rec.CertSerial, err)
	}
	return nil
}

func (r clientRoleRepository) Get(ctx context.Context, certSerial string) (store.ClientRoleRecord, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT cert_serial, role, created_at FROM client_roles WHERE cert_serial = ?`, certSerial)
	return scanClientRole(row)
}

func (r clientRoleRepository) List(ctx context.Context) ([]store.ClientRoleRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT cert_serial, role, created_at FROM client_roles ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: listing client roles: %w", err)
	}
	defer rows.Close()

	var out []store.ClientRoleRecord
	for rows.Next() {
		rec, err := scanClientRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func scanClientRole(row scanner) (store.ClientRoleRecord, error) {
	var (
		rec       store.ClientRoleRecord
		role      string
		createdAt string
	)
	err := row.Scan(&rec.CertSerial, &role, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ClientRoleRecord{}, store.ErrNotFound
		}
		return store.ClientRoleRecord{}, fmt.Errorf("sqlite: scanning client role: %w", err)
	}
	rec.Role = store.ClientRole(role)
	if rec.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return store.ClientRoleRecord{}, fmt.Errorf("sqlite: parsing created_at: %w", err)
	}
	return rec, nil
}
