package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/prampec/trustmate/internal/store"
)

type profileRepository struct {
	db *sql.DB
}

func (r profileRepository) Upsert(ctx context.Context, rec store.ProfileRecord) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO profiles (name, version, data, created_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (name, version) DO UPDATE SET data = excluded.data, created_at = excluded.created_at`,
		rec.Name, rec.Version, rec.Data, rec.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("postgres: upserting profile %s v%d: %w", rec.Name, rec.Version, err)
	}
	return nil
}

func (r profileRepository) Get(ctx context.Context, name string) (store.ProfileRecord, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT name, version, data, created_at FROM profiles
		WHERE name = $1 ORDER BY version DESC LIMIT 1`, name)

	var rec store.ProfileRecord
	err := row.Scan(&rec.Name, &rec.Version, &rec.Data, &rec.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ProfileRecord{}, store.ErrNotFound
		}
		return store.ProfileRecord{}, fmt.Errorf("postgres: getting profile %s: %w", name, err)
	}
	return rec, nil
}

func (r profileRepository) List(ctx context.Context) ([]store.ProfileRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT name, version, data, created_at FROM profiles ORDER BY name ASC, version ASC`)
	if err != nil {
		return nil, fmt.Errorf("postgres: listing profiles: %w", err)
	}
	defer rows.Close()

	var out []store.ProfileRecord
	for rows.Next() {
		var rec store.ProfileRecord
		if err := rows.Scan(&rec.Name, &rec.Version, &rec.Data, &rec.CreatedAt); err != nil {
			return nil, fmt.Errorf("postgres: scanning profile: %w", err)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}
