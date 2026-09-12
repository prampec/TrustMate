package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/prampec/trustmate/internal/store"
)

type profileRepository struct {
	db *sql.DB
}

func (r profileRepository) Upsert(ctx context.Context, rec store.ProfileRecord) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO profiles (name, version, data, created_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (name, version) DO UPDATE SET data = excluded.data, created_at = excluded.created_at`,
		rec.Name, rec.Version, rec.Data, rec.CreatedAt.UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("sqlite: upserting profile %s v%d: %w", rec.Name, rec.Version, err)
	}
	return nil
}

func (r profileRepository) Get(ctx context.Context, name string) (store.ProfileRecord, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT name, version, data, created_at FROM profiles
		WHERE name = ? ORDER BY version DESC LIMIT 1`, name)

	var rec store.ProfileRecord
	var createdAt string
	err := row.Scan(&rec.Name, &rec.Version, &rec.Data, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ProfileRecord{}, store.ErrNotFound
		}
		return store.ProfileRecord{}, fmt.Errorf("sqlite: getting profile %s: %w", name, err)
	}
	if rec.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return store.ProfileRecord{}, fmt.Errorf("sqlite: parsing created_at: %w", err)
	}
	return rec, nil
}

func (r profileRepository) List(ctx context.Context) ([]store.ProfileRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT name, version, data, created_at FROM profiles ORDER BY name ASC, version ASC`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: listing profiles: %w", err)
	}
	defer rows.Close()

	var out []store.ProfileRecord
	for rows.Next() {
		var rec store.ProfileRecord
		var createdAt string
		if err := rows.Scan(&rec.Name, &rec.Version, &rec.Data, &createdAt); err != nil {
			return nil, fmt.Errorf("sqlite: scanning profile: %w", err)
		}
		if rec.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
			return nil, fmt.Errorf("sqlite: parsing created_at: %w", err)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}
