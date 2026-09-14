package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/prampec/trustmate/internal/store"
)

// pgUniqueViolation is the SQLSTATE Postgres returns for a UNIQUE
// constraint violation. See https://www.postgresql.org/docs/current/errcodes-appendix.html.
const pgUniqueViolation = "23505"

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation
}

type acmeEABTokenRepository struct {
	db *sql.DB
}

func (r acmeEABTokenRepository) Create(ctx context.Context, rec store.ACMEEABTokenRecord) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO acme_eab_tokens (key_id, hmac_key, role, created_at, expires_at, consumed)
		VALUES ($1, $2, $3, $4, $5, FALSE)`,
		rec.KeyID, rec.HMACKey, string(rec.Role), rec.CreatedAt.UTC(), rec.ExpiresAt.UTC())
	if err != nil {
		return fmt.Errorf("postgres: creating acme eab token %s: %w", rec.KeyID, err)
	}
	return nil
}

func (r acmeEABTokenRepository) Get(ctx context.Context, keyID string) (store.ACMEEABTokenRecord, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT key_id, hmac_key, role, created_at, expires_at, consumed
		FROM acme_eab_tokens WHERE key_id = $1`, keyID)

	var (
		rec  store.ACMEEABTokenRecord
		role string
	)
	err := row.Scan(&rec.KeyID, &rec.HMACKey, &role, &rec.CreatedAt, &rec.ExpiresAt, &rec.Consumed)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ACMEEABTokenRecord{}, store.ErrNotFound
		}
		return store.ACMEEABTokenRecord{}, fmt.Errorf("postgres: getting acme eab token %s: %w", keyID, err)
	}
	rec.Role = store.ClientRole(role)
	return rec, nil
}

func (r acmeEABTokenRepository) MarkConsumed(ctx context.Context, keyID string, now time.Time) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE acme_eab_tokens SET consumed = TRUE
		WHERE key_id = $1 AND consumed = FALSE AND expires_at > $2`,
		keyID, now.UTC())
	if err != nil {
		return fmt.Errorf("postgres: consuming acme eab token %s: %w", keyID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: consuming acme eab token %s: %w", keyID, err)
	}
	if n > 0 {
		return nil
	}
	// The claim didn't affect a row -- distinguish "no such token" from
	// "exists but already consumed/expired" only on this (uncommon)
	// path, since the common (successful-claim) path shouldn't pay for
	// an extra lookup.
	var exists int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM acme_eab_tokens WHERE key_id = $1`, keyID).Scan(&exists); err != nil {
		return fmt.Errorf("postgres: checking acme eab token %s: %w", keyID, err)
	}
	if exists == 0 {
		return store.ErrNotFound
	}
	return store.ErrAlreadyConsumed
}

type acmeAccountRepository struct {
	db *sql.DB
}

func (r acmeAccountRepository) Create(ctx context.Context, rec store.ACMEAccountRecord) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO acme_accounts (id, jwk_thumbprint, public_key_jwk, role, eab_key_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		rec.ID, rec.JWKThumbprint, rec.PublicKeyJWK, string(rec.Role), rec.EABKeyID, rec.CreatedAt.UTC())
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: creating acme account %s: %w", rec.ID, err)
	}
	return nil
}

const acmeAccountColumns = `id, jwk_thumbprint, public_key_jwk, role, eab_key_id, created_at`

func (r acmeAccountRepository) GetByThumbprint(ctx context.Context, thumbprint string) (store.ACMEAccountRecord, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+acmeAccountColumns+` FROM acme_accounts WHERE jwk_thumbprint = $1`, thumbprint)
	return scanACMEAccount(row)
}

func (r acmeAccountRepository) GetByID(ctx context.Context, id string) (store.ACMEAccountRecord, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+acmeAccountColumns+` FROM acme_accounts WHERE id = $1`, id)
	return scanACMEAccount(row)
}

func scanACMEAccount(row scanner) (store.ACMEAccountRecord, error) {
	var (
		rec  store.ACMEAccountRecord
		role string
	)
	err := row.Scan(&rec.ID, &rec.JWKThumbprint, &rec.PublicKeyJWK, &role, &rec.EABKeyID, &rec.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ACMEAccountRecord{}, store.ErrNotFound
		}
		return store.ACMEAccountRecord{}, fmt.Errorf("postgres: scanning acme account: %w", err)
	}
	rec.Role = store.ClientRole(role)
	return rec, nil
}

type acmeOrderRepository struct {
	db *sql.DB
}

func (r acmeOrderRepository) Create(ctx context.Context, rec store.ACMEOrderRecord) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO acme_orders (id, account_id, identifier, status, cert_serial, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		rec.ID, rec.AccountID, rec.Identifier, string(rec.Status), rec.CertSerial, rec.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("postgres: creating acme order %s: %w", rec.ID, err)
	}
	return nil
}

func (r acmeOrderRepository) Get(ctx context.Context, id string) (store.ACMEOrderRecord, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, account_id, identifier, status, cert_serial, created_at
		FROM acme_orders WHERE id = $1`, id)

	var (
		rec    store.ACMEOrderRecord
		status string
	)
	err := row.Scan(&rec.ID, &rec.AccountID, &rec.Identifier, &status, &rec.CertSerial, &rec.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ACMEOrderRecord{}, store.ErrNotFound
		}
		return store.ACMEOrderRecord{}, fmt.Errorf("postgres: getting acme order %s: %w", id, err)
	}
	rec.Status = store.ACMEOrderStatus(status)
	return rec, nil
}

func (r acmeOrderRepository) UpdateStatus(ctx context.Context, id string, fromStatus, toStatus store.ACMEOrderStatus, certSerial string) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE acme_orders SET status = $1, cert_serial = $2 WHERE id = $3 AND status = $4`,
		string(toStatus), certSerial, id, string(fromStatus))
	if err != nil {
		return false, fmt.Errorf("postgres: updating acme order %s: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("postgres: updating acme order %s: %w", id, err)
	}
	if n > 0 {
		return true, nil
	}
	// The CAS didn't affect a row -- distinguish "no such order" from
	// "exists but not in fromStatus" (a lost race, not an error) only on
	// this (uncommon) path, matching MarkConsumed's pattern above.
	var exists int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM acme_orders WHERE id = $1`, id).Scan(&exists); err != nil {
		return false, fmt.Errorf("postgres: checking acme order %s: %w", id, err)
	}
	if exists == 0 {
		return false, store.ErrNotFound
	}
	return false, nil
}

type acmeNonceRepository struct {
	db *sql.DB
}

func (r acmeNonceRepository) Issue(ctx context.Context, expiresAt time.Time) (string, error) {
	// store.ACMENonceBytes -- see internal/store/sqlite/acme.go's
	// identical comment on why Issue doesn't loop-retry a collision.
	buf := make([]byte, store.ACMENonceBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("postgres: generating acme nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(buf)

	_, err := r.db.ExecContext(ctx, `INSERT INTO acme_nonces (nonce, expires_at) VALUES ($1, $2)`,
		nonce, expiresAt.UTC())
	if err != nil {
		return "", fmt.Errorf("postgres: persisting acme nonce: %w", err)
	}
	return nonce, nil
}

func (r acmeNonceRepository) ConsumeIfValid(ctx context.Context, nonce string, now time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM acme_nonces WHERE nonce = $1 AND expires_at > $2`,
		nonce, now.UTC())
	if err != nil {
		return false, fmt.Errorf("postgres: consuming acme nonce: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("postgres: consuming acme nonce: %w", err)
	}
	return n > 0, nil
}
