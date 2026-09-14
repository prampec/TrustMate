package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/prampec/trustmate/internal/store"
)

type clientRoleRepository struct {
	db *sql.DB
}

func (r clientRoleRepository) Assign(ctx context.Context, rec store.ClientRoleRecord) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO client_roles (cert_serial, role, created_at) VALUES ($1, $2, $3)
		ON CONFLICT (cert_serial) DO UPDATE SET role = excluded.role`,
		rec.CertSerial, string(rec.Role), rec.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("postgres: assigning role to certificate %s: %w", rec.CertSerial, err)
	}
	return nil
}

func (r clientRoleRepository) Get(ctx context.Context, certSerial string) (store.ClientRoleRecord, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT cert_serial, role, created_at FROM client_roles WHERE cert_serial = $1`, certSerial)
	return scanClientRole(row)
}

func (r clientRoleRepository) List(ctx context.Context) ([]store.ClientRoleRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT cert_serial, role, created_at FROM client_roles ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("postgres: listing client roles: %w", err)
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
		rec  store.ClientRoleRecord
		role string
	)
	err := row.Scan(&rec.CertSerial, &role, &rec.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ClientRoleRecord{}, store.ErrNotFound
		}
		return store.ClientRoleRecord{}, fmt.Errorf("postgres: scanning client role: %w", err)
	}
	rec.Role = store.ClientRole(role)
	return rec, nil
}
