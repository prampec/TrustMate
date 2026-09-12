package sqlite

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
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.Serial, string(rec.Kind), rec.ProfileName, rec.Subject, issuer,
		rec.NotBefore.UTC().Format(time.RFC3339), rec.NotAfter.UTC().Format(time.RFC3339),
		rec.PEM, rec.KeyRef, rec.CreatedAt.UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("sqlite: creating certificate %s: %w", rec.Serial, err)
	}
	return nil
}

const certificateColumns = `serial, kind, profile_name, subject, issuer_serial, not_before, not_after, pem, key_ref, created_at, revoked_at, revocation_reason`

func (r certificateRepository) GetBySerial(ctx context.Context, serial string) (store.CertificateRecord, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT `+certificateColumns+`
		FROM certificates WHERE serial = ?`, serial)
	return scanCertificate(row)
}

func (r certificateRepository) FindByKind(ctx context.Context, kind store.CertKind) ([]store.CertificateRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+certificateColumns+`
		FROM certificates WHERE kind = ? ORDER BY created_at ASC`, string(kind))
	if err != nil {
		return nil, fmt.Errorf("sqlite: finding certificates by kind %s: %w", kind, err)
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

func (r certificateRepository) GetLatestByProfile(ctx context.Context, profileName string) (store.CertificateRecord, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT `+certificateColumns+`
		FROM certificates WHERE profile_name = ? ORDER BY created_at DESC LIMIT 1`, profileName)
	return scanCertificate(row)
}

func (r certificateRepository) Revoke(ctx context.Context, serial string, reason string, at time.Time) error {
	rec, err := r.GetBySerial(ctx, serial)
	if err != nil {
		return err
	}
	if rec.RevokedAt != nil {
		return store.ErrAlreadyRevoked
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE certificates SET revoked_at = ?, revocation_reason = ?
		WHERE serial = ? AND revoked_at IS NULL`,
		at.UTC().Format(time.RFC3339), reason, serial)
	if err != nil {
		return fmt.Errorf("sqlite: revoking certificate %s: %w", serial, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: revoking certificate %s: %w", serial, err)
	}
	if n == 0 {
		return store.ErrAlreadyRevoked
	}
	return nil
}

func (r certificateRepository) FindRevoked(ctx context.Context) ([]store.CertificateRecord, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+certificateColumns+`
		FROM certificates WHERE revoked_at IS NOT NULL ORDER BY revoked_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: finding revoked certificates: %w", err)
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
		rec                 store.CertificateRecord
		kind                string
		issuer              sql.NullString
		notBefore, notAfter string
		createdAt           string
		revokedAt           sql.NullString
		revocationReason    string
	)
	err := row.Scan(&rec.Serial, &kind, &rec.ProfileName, &rec.Subject, &issuer,
		&notBefore, &notAfter, &rec.PEM, &rec.KeyRef, &createdAt, &revokedAt, &revocationReason)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.CertificateRecord{}, store.ErrNotFound
		}
		return store.CertificateRecord{}, fmt.Errorf("sqlite: scanning certificate: %w", err)
	}

	rec.Kind = store.CertKind(kind)
	rec.IssuerSerial = issuer.String
	rec.RevocationReason = revocationReason
	if rec.NotBefore, err = time.Parse(time.RFC3339, notBefore); err != nil {
		return store.CertificateRecord{}, fmt.Errorf("sqlite: parsing not_before: %w", err)
	}
	if rec.NotAfter, err = time.Parse(time.RFC3339, notAfter); err != nil {
		return store.CertificateRecord{}, fmt.Errorf("sqlite: parsing not_after: %w", err)
	}
	if rec.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return store.CertificateRecord{}, fmt.Errorf("sqlite: parsing created_at: %w", err)
	}
	if revokedAt.Valid {
		t, err := time.Parse(time.RFC3339, revokedAt.String)
		if err != nil {
			return store.CertificateRecord{}, fmt.Errorf("sqlite: parsing revoked_at: %w", err)
		}
		rec.RevokedAt = &t
	}
	return rec, nil
}
