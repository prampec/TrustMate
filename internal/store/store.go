// Package store is the issued-certificate ledger: serial number
// allocation (via random serials -- see internal/pki), revocation
// records (added when the revocation module lands), and the audit log,
// behind an interface so a Postgres implementation can sit alongside the
// SQLite default without touching call sites. See docs/design.md,
// module 6.
package store

import (
	"context"
	"time"
)

// CertKind distinguishes the structural role of a certificate row.
type CertKind string

const (
	CertKindRoot         CertKind = "root"
	CertKindIntermediate CertKind = "intermediate"
	CertKindLeaf         CertKind = "leaf"
)

// CertificateRecord is one row of the certificate ledger.
type CertificateRecord struct {
	Serial string // decimal big.Int.String(); primary key
	Kind   CertKind
	// ProfileName is empty for root/intermediate rows -- those are
	// generated through CA-specific bootstrap logic, not a leaf profile.
	ProfileName string
	Subject     string
	// IssuerSerial is empty for the root (self-signed).
	IssuerSerial string
	NotBefore    time.Time
	NotAfter     time.Time
	PEM          []byte
	// KeyRef is the keystore.KeyRef (as a string) holding this
	// certificate's private key server-side, or empty when the server
	// doesn't keep custody (e.g. the admin access leaf).
	KeyRef    string
	CreatedAt time.Time
}

// ProfileRecord is one version of a named certificate profile, stored as
// its canonical serialized snapshot for audit/versioning.
type ProfileRecord struct {
	Name      string
	Version   int
	Data      []byte
	CreatedAt time.Time
}

// AuditEntry is one append-only audit log row.
type AuditEntry struct {
	ID        int64
	Timestamp time.Time
	Actor     string
	Action    string
	Target    string
	Detail    string
}

type CertificateRepository interface {
	Create(ctx context.Context, rec CertificateRecord) error
	GetBySerial(ctx context.Context, serial string) (CertificateRecord, error)
	FindByKind(ctx context.Context, kind CertKind) ([]CertificateRecord, error)
	// GetLatestByProfile returns the most recently created certificate
	// issued against the given profile name (e.g. the bootstrap
	// server-tls leaf), so callers don't need a bespoke query.
	GetLatestByProfile(ctx context.Context, profileName string) (CertificateRecord, error)
}

type ProfileRepository interface {
	Upsert(ctx context.Context, rec ProfileRecord) error
	// Get returns the latest version of the named profile.
	Get(ctx context.Context, name string) (ProfileRecord, error)
	List(ctx context.Context) ([]ProfileRecord, error)
}

type AuditRepository interface {
	Append(ctx context.Context, entry AuditEntry) error
	List(ctx context.Context, limit int) ([]AuditEntry, error)
}

// Store is the top-level datastore handle.
type Store interface {
	Ping(ctx context.Context) error
	Close() error
	Certificates() CertificateRepository
	Profiles() ProfileRepository
	Audit() AuditRepository
}

// ErrNotFound is returned by Get-style methods when no matching row exists.
var ErrNotFound = errNotFound{}

type errNotFound struct{}

func (errNotFound) Error() string { return "store: not found" }
