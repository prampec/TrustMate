package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	sqlite3 "modernc.org/sqlite"

	"github.com/prampec/trustmate/internal/store"
)

// sqliteConstraint and sqliteConstraintUnique are the (generic and
// UNIQUE-specific) SQLite result codes for a constraint violation. See
// https://www.sqlite.org/rescode.html#constraint. Checking both covers
// builds where SQLite's extended result codes aren't enabled and only
// the generic code comes back.
const (
	sqliteConstraint       = 19
	sqliteConstraintUnique = 2067
)

func isUniqueViolation(err error) bool {
	var sqliteErr *sqlite3.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	code := sqliteErr.Code()
	return code == sqliteConstraint || code == sqliteConstraintUnique
}

type acmeEABTokenRepository struct {
	db *sql.DB
}

func (r acmeEABTokenRepository) Create(ctx context.Context, rec store.ACMEEABTokenRecord) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO acme_eab_tokens (key_id, hmac_key, role, created_at, expires_at, consumed)
		VALUES (?, ?, ?, ?, ?, 0)`,
		rec.KeyID, rec.HMACKey, string(rec.Role), rec.CreatedAt.UTC().Format(time.RFC3339), rec.ExpiresAt.UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("sqlite: creating acme eab token %s: %w", rec.KeyID, err)
	}
	return nil
}

func (r acmeEABTokenRepository) Get(ctx context.Context, keyID string) (store.ACMEEABTokenRecord, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT key_id, hmac_key, role, created_at, expires_at, consumed
		FROM acme_eab_tokens WHERE key_id = ?`, keyID)

	var (
		rec       store.ACMEEABTokenRecord
		role      string
		createdAt string
		expiresAt string
		consumed  int
	)
	err := row.Scan(&rec.KeyID, &rec.HMACKey, &role, &createdAt, &expiresAt, &consumed)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ACMEEABTokenRecord{}, store.ErrNotFound
		}
		return store.ACMEEABTokenRecord{}, fmt.Errorf("sqlite: getting acme eab token %s: %w", keyID, err)
	}
	rec.Role = store.ClientRole(role)
	rec.Consumed = consumed != 0
	if rec.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return store.ACMEEABTokenRecord{}, fmt.Errorf("sqlite: parsing created_at: %w", err)
	}
	if rec.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt); err != nil {
		return store.ACMEEABTokenRecord{}, fmt.Errorf("sqlite: parsing expires_at: %w", err)
	}
	return rec, nil
}

func (r acmeEABTokenRepository) MarkConsumed(ctx context.Context, keyID string, now time.Time) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE acme_eab_tokens SET consumed = 1
		WHERE key_id = ? AND consumed = 0 AND expires_at > ?`,
		keyID, now.UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("sqlite: consuming acme eab token %s: %w", keyID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: consuming acme eab token %s: %w", keyID, err)
	}
	if n > 0 {
		return nil
	}
	// The claim didn't affect a row -- distinguish "no such token" from
	// "exists but already consumed/expired" only on this (uncommon)
	// path, since the common (successful-claim) path shouldn't pay for
	// an extra lookup.
	var exists int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM acme_eab_tokens WHERE key_id = ?`, keyID).Scan(&exists); err != nil {
		return fmt.Errorf("sqlite: checking acme eab token %s: %w", keyID, err)
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
		VALUES (?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.JWKThumbprint, rec.PublicKeyJWK, string(rec.Role), rec.EABKeyID, rec.CreatedAt.UTC().Format(time.RFC3339))
	if err != nil {
		if isUniqueViolation(err) {
			return store.ErrAlreadyExists
		}
		return fmt.Errorf("sqlite: creating acme account %s: %w", rec.ID, err)
	}
	return nil
}

const acmeAccountColumns = `id, jwk_thumbprint, public_key_jwk, role, eab_key_id, created_at`

func (r acmeAccountRepository) GetByThumbprint(ctx context.Context, thumbprint string) (store.ACMEAccountRecord, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+acmeAccountColumns+` FROM acme_accounts WHERE jwk_thumbprint = ?`, thumbprint)
	return scanACMEAccount(row)
}

func (r acmeAccountRepository) GetByID(ctx context.Context, id string) (store.ACMEAccountRecord, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+acmeAccountColumns+` FROM acme_accounts WHERE id = ?`, id)
	return scanACMEAccount(row)
}

func scanACMEAccount(row scanner) (store.ACMEAccountRecord, error) {
	var (
		rec       store.ACMEAccountRecord
		role      string
		createdAt string
	)
	err := row.Scan(&rec.ID, &rec.JWKThumbprint, &rec.PublicKeyJWK, &role, &rec.EABKeyID, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ACMEAccountRecord{}, store.ErrNotFound
		}
		return store.ACMEAccountRecord{}, fmt.Errorf("sqlite: scanning acme account: %w", err)
	}
	rec.Role = store.ClientRole(role)
	if rec.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return store.ACMEAccountRecord{}, fmt.Errorf("sqlite: parsing created_at: %w", err)
	}
	return rec, nil
}

type acmeOrderRepository struct {
	db *sql.DB
}

func (r acmeOrderRepository) Create(ctx context.Context, rec store.ACMEOrderRecord) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO acme_orders (id, account_id, identifier, status, cert_serial, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.AccountID, rec.Identifier, string(rec.Status), rec.CertSerial, rec.CreatedAt.UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("sqlite: creating acme order %s: %w", rec.ID, err)
	}
	return nil
}

func (r acmeOrderRepository) Get(ctx context.Context, id string) (store.ACMEOrderRecord, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, account_id, identifier, status, cert_serial, created_at
		FROM acme_orders WHERE id = ?`, id)

	var (
		rec       store.ACMEOrderRecord
		status    string
		createdAt string
	)
	err := row.Scan(&rec.ID, &rec.AccountID, &rec.Identifier, &status, &rec.CertSerial, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ACMEOrderRecord{}, store.ErrNotFound
		}
		return store.ACMEOrderRecord{}, fmt.Errorf("sqlite: getting acme order %s: %w", id, err)
	}
	rec.Status = store.ACMEOrderStatus(status)
	if rec.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return store.ACMEOrderRecord{}, fmt.Errorf("sqlite: parsing created_at: %w", err)
	}
	return rec, nil
}

func (r acmeOrderRepository) UpdateStatus(ctx context.Context, id string, fromStatus, toStatus store.ACMEOrderStatus, certSerial string) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE acme_orders SET status = ?, cert_serial = ? WHERE id = ? AND status = ?`,
		string(toStatus), certSerial, id, string(fromStatus))
	if err != nil {
		return false, fmt.Errorf("sqlite: updating acme order %s: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("sqlite: updating acme order %s: %w", id, err)
	}
	if n > 0 {
		return true, nil
	}
	// The CAS didn't affect a row -- distinguish "no such order" from
	// "exists but not in fromStatus" (a lost race, not an error) only on
	// this (uncommon) path, matching MarkConsumed's pattern above.
	var exists int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM acme_orders WHERE id = ?`, id).Scan(&exists); err != nil {
		return false, fmt.Errorf("sqlite: checking acme order %s: %w", id, err)
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
	// store.ACMENonceBytes (192 bits) follows the same CSPRNG-entropy
	// reasoning as internal/pki.GenerateSerial: an accidental collision
	// is astronomically unlikely, so -- like GenerateSerial -- Issue
	// doesn't loop-retry on one.
	buf := make([]byte, store.ACMENonceBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("sqlite: generating acme nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(buf)

	_, err := r.db.ExecContext(ctx, `INSERT INTO acme_nonces (nonce, expires_at) VALUES (?, ?)`,
		nonce, expiresAt.UTC().Format(time.RFC3339))
	if err != nil {
		return "", fmt.Errorf("sqlite: persisting acme nonce: %w", err)
	}
	return nonce, nil
}

func (r acmeNonceRepository) ConsumeIfValid(ctx context.Context, nonce string, now time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM acme_nonces WHERE nonce = ? AND expires_at > ?`,
		nonce, now.UTC().Format(time.RFC3339))
	if err != nil {
		return false, fmt.Errorf("sqlite: consuming acme nonce: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("sqlite: consuming acme nonce: %w", err)
	}
	return n > 0, nil
}
