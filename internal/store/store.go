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

	// RevokedAt is nil for a certificate that has never been revoked.
	RevokedAt *time.Time
	// RevocationReason is one of the RFC 5280 reason strings the api
	// package validates against (e.g. "keyCompromise"); empty when never
	// revoked.
	RevocationReason string
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
	// Revoke marks serial revoked at 'at' with the given reason. Returns
	// ErrNotFound if no such serial exists, or ErrAlreadyRevoked if it was
	// already revoked.
	Revoke(ctx context.Context, serial string, reason string, at time.Time) error
	// FindRevoked returns every certificate with a non-nil RevokedAt, for
	// the CRL builder to populate RevokedCertificateEntries from.
	FindRevoked(ctx context.Context) ([]CertificateRecord, error)
}

// ClientRole is an API caller's access level, bound to a client
// certificate's serial via ClientRoleRepository -- independent of which
// profile issued that certificate. See docs/design.md's Phase 3 roadmap
// entry and functional goal "Roles are: Admin ... Manager ...".
type ClientRole string

const (
	// RoleAdmin can alter configuration: profiles and the client roster.
	// It is a strict superset of RoleManager.
	RoleAdmin ClientRole = "admin"
	// RoleManager can list, issue, and revoke certificates.
	RoleManager ClientRole = "manager"
)

// ClientRoleRecord binds a certificate's serial to a role.
type ClientRoleRecord struct {
	CertSerial string
	Role       ClientRole
	CreatedAt  time.Time
}

type ClientRoleRepository interface {
	Assign(ctx context.Context, rec ClientRoleRecord) error
	// Get returns ErrNotFound if certSerial has no role assigned.
	Get(ctx context.Context, certSerial string) (ClientRoleRecord, error)
	List(ctx context.Context) ([]ClientRoleRecord, error)
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
	ClientRoles() ClientRoleRepository
}

// ErrNotFound is returned by Get-style methods when no matching row exists.
var ErrNotFound = errNotFound{}

// ErrAlreadyRevoked is returned by CertificateRepository.Revoke when the
// target certificate was already revoked.
var ErrAlreadyRevoked = errAlreadyRevoked{}

type errNotFound struct{}

func (errNotFound) Error() string { return "store: not found" }

type errAlreadyRevoked struct{}

func (errAlreadyRevoked) Error() string { return "store: certificate already revoked" }
