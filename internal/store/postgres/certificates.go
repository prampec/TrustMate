package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/prampec/trustmate/internal/store"
)

type certificateRepository struct {
	db *sql.DB
}

func (r certificateRepository) Create(ctx context.Context, rec store.CertificateRecord) error {
	issuer := sql.NullString{String: rec.IssuerSerial, Valid: rec.IssuerSerial != ""}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO certificates (serial, kind, profile_name, subject, issuer_serial, not_before, not_after, pem, key_ref, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		rec.Serial, string(rec.Kind), rec.ProfileName, rec.Subject, issuer,
		rec.NotBefore.UTC(), rec.NotAfter.UTC(), rec.PEM, rec.KeyRef, rec.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("postgres: creating certificate %s: %w", rec.Serial, err)
	}
	return nil
}

const certificateColumns = `serial, kind, profile_name, subject, issuer_serial, not_before, not_after, pem, key_ref, created_at, revoked_at, revocation_reason`

func (r certificateRepository) GetBySerial(ctx context.Context, serial string) (store.CertificateRecord, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT `+certificateColumns+`
		FROM certificates WHERE serial = $1`, serial)
	return scanCertificate(row)
}

// FindByKind orders by created_at ASC, seq ASC. Postgres has no implicit
// rowid the way SQLite does (certificates has a TEXT PRIMARY KEY), so
// certificates.seq (a GENERATED ALWAYS AS IDENTITY column, see
// migrations/0001_init.sql) plays the same insertion-order tiebreak role
// -- two rows inserted in the same wall-clock instant would otherwise
// sort in an undefined order.
func (r certificateRepository) FindByKind(ctx context.Context, kind store.CertKind) ([]store.CertificateRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+certificateColumns+`
		FROM certificates WHERE kind = $1 ORDER BY created_at ASC, seq ASC`, string(kind))
	if err != nil {
		return nil, fmt.Errorf("postgres: finding certificates by kind %s: %w", kind, err)
	}
	defer rows.Close()

	var out []store.CertificateRecord
	for rows.Next() {
		rec, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// GetLatestByProfile orders by created_at DESC, seq DESC -- see
// FindByKind's comment on why seq is needed as a tiebreak.
func (r certificateRepository) GetLatestByProfile(ctx context.Context, profileName string) (store.CertificateRecord, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT `+certificateColumns+`
		FROM certificates WHERE profile_name = $1 ORDER BY created_at DESC, seq DESC LIMIT 1`, profileName)
	return scanCertificate(row)
}

// Revoke tries the UPDATE optimistically first, saving the common
// (successful) case a round trip -- RowsAffected alone already tells us
// whether it took effect. Only the uncommon path (0 rows affected) needs
// a follow-up GetBySerial, to distinguish "no such certificate" from
// "already revoked".
func (r certificateRepository) Revoke(ctx context.Context, serial string, reason string, at time.Time) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE certificates SET revoked_at = $1, revocation_reason = $2
		WHERE serial = $3 AND revoked_at IS NULL`,
		at.UTC(), reason, serial)
	if err != nil {
		return fmt.Errorf("postgres: revoking certificate %s: %w", serial, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: revoking certificate %s: %w", serial, err)
	}
	if n == 0 {
		if _, err := r.GetBySerial(ctx, serial); err != nil {
			return err
		}
		return store.ErrAlreadyRevoked
	}
	return nil
}

func (r certificateRepository) FindRevoked(ctx context.Context) ([]store.CertificateRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+certificateColumns+`
		FROM certificates WHERE revoked_at IS NOT NULL ORDER BY revoked_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("postgres: finding revoked certificates: %w", err)
	}
	defer rows.Close()

	var out []store.CertificateRecord
	for rows.Next() {
		rec, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanCertificate(row scanner) (store.CertificateRecord, error) {
	var (
		rec              store.CertificateRecord
		kind             string
		issuer           sql.NullString
		notBefore        time.Time
		notAfter         time.Time
		createdAt        time.Time
		revokedAt        sql.NullTime
		revocationReason string
	)
	err := row.Scan(&rec.Serial, &kind, &rec.ProfileName, &rec.Subject, &issuer,
		&notBefore, &notAfter, &rec.PEM, &rec.KeyRef, &createdAt, &revokedAt, &revocationReason)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.CertificateRecord{}, store.ErrNotFound
		}
		return store.CertificateRecord{}, fmt.Errorf("postgres: scanning certificate: %w", err)
	}

	rec.Kind = store.CertKind(kind)
	rec.IssuerSerial = issuer.String
	rec.RevocationReason = revocationReason
	rec.NotBefore = notBefore
	rec.NotAfter = notAfter
	rec.CreatedAt = createdAt
	if revokedAt.Valid {
		rec.RevokedAt = &revokedAt.Time
	}
	return rec, nil
}
