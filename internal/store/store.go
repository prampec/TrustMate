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

// ACMEEABTokenRecord is an admin-issued, single-use External Account
// Binding credential (RFC 8555 section 7.3.4) -- see docs/design.md's
// Phase 5 roadmap entry. TrustMate uses EAB, not http-01/dns-01 domain
// challenges, as its ACME authorization mechanism: an admin already
// vouches for the requester out-of-band (the same trust boundary as
// today's POST /v1/clients), and ACME automates the mechanics of
// enrollment/renewal on top of that, not a new authorization decision.
type ACMEEABTokenRecord struct {
	KeyID     string
	HMACKey   []byte
	Role      ClientRole
	CreatedAt time.Time
	ExpiresAt time.Time
	Consumed  bool
}

// ACMEAccountRecord is an ACME account bound to one (now-consumed) EAB
// token. JWKThumbprint (RFC 7638) is the account's stable identifier,
// derived from its public key; PublicKeyJWK is the canonical JWK JSON
// used to verify that account's later request signatures.
type ACMEAccountRecord struct {
	ID            string
	JWKThumbprint string
	PublicKeyJWK  []byte
	Role          ClientRole
	EABKeyID      string
	CreatedAt     time.Time
}

// ACMEOrderStatus is the lifecycle state of an ACMEOrderRecord.
type ACMEOrderStatus string

const (
	// ACMEOrderStatusReady means authorized (EAB already satisfied
	// authorization -- see ACMEOrderRecord's doc comment) and awaiting
	// finalize. TrustMate's orders skip RFC 8555's "pending" status:
	// there's no separate challenge/authorization step the way
	// http-01/dns-01 requires, so an order is "ready" the instant it's
	// created.
	ACMEOrderStatusReady ACMEOrderStatus = "ready"
	// ACMEOrderStatusProcessing means finalize has claimed the order
	// (so a concurrent or retried finalize call must not also issue a
	// certificate for it) but issuance hasn't yet been durably recorded
	// as ACMEOrderStatusValid. An order stuck here after a failure is a
	// signal for operator attention, not something finalize will
	// silently retry into a second certificate.
	ACMEOrderStatusProcessing ACMEOrderStatus = "processing"
	// ACMEOrderStatusValid means finalize succeeded; CertSerial is set.
	ACMEOrderStatusValid ACMEOrderStatus = "valid"
)

// ACMEOrderRecord tracks one certificate order.
type ACMEOrderRecord struct {
	ID         string
	AccountID  string
	Identifier string
	Status     ACMEOrderStatus
	CertSerial string
	CreatedAt  time.Time
}

type ACMEEABTokenRepository interface {
	Create(ctx context.Context, rec ACMEEABTokenRecord) error
	// Get returns ErrNotFound if keyID doesn't exist.
	Get(ctx context.Context, keyID string) (ACMEEABTokenRecord, error)
	// MarkConsumed atomically claims the token: it flips Consumed to
	// true only if the token exists, was not already consumed, and
	// hasn't expired as of now. This is the actual single-use guarantee
	// -- callers must gate account creation on its success, not treat
	// it as a fire-and-forget bookkeeping update after the fact, or two
	// concurrent requests presenting the same token can both succeed.
	// Returns ErrNotFound if keyID doesn't exist, or ErrAlreadyConsumed
	// if it exists but was already consumed or has expired.
	MarkConsumed(ctx context.Context, keyID string, now time.Time) error
}

type ACMEAccountRepository interface {
	// Create returns ErrAlreadyExists if an account with rec.JWKThumbprint
	// already exists -- possible even after a caller's own
	// GetByThumbprint idempotency check came back empty, if a concurrent
	// new-account request for the same key won the race first. Callers
	// must treat that as the RFC 8555 section 7.3.1 idempotent case (look
	// the winning account back up and return it), not as a server error.
	Create(ctx context.Context, rec ACMEAccountRecord) error
	// GetByThumbprint returns ErrNotFound if no account has that JWK
	// thumbprint.
	GetByThumbprint(ctx context.Context, thumbprint string) (ACMEAccountRecord, error)
	// GetByID returns ErrNotFound if id doesn't exist.
	GetByID(ctx context.Context, id string) (ACMEAccountRecord, error)
}

type ACMEOrderRepository interface {
	Create(ctx context.Context, rec ACMEOrderRecord) error
	// Get returns ErrNotFound if id doesn't exist.
	Get(ctx context.Context, id string) (ACMEOrderRecord, error)
	// UpdateStatus compare-and-swaps the order named by id: it sets
	// Status to toStatus and CertSerial to certSerial only if the order's
	// current status is still fromStatus, returning applied=false (with a
	// nil error) if not -- e.g. a concurrent finalize already claimed the
	// order first. This is the actual single-claim guarantee finalize
	// depends on; a plain read-then-write Update would let two concurrent
	// finalize calls both observe "ready" and both issue a certificate.
	// Returns ErrNotFound if id doesn't exist at all.
	UpdateStatus(ctx context.Context, id string, fromStatus, toStatus ACMEOrderStatus, certSerial string) (applied bool, err error)
}

// ACMENonceRepository backs RFC 8555's replay-nonce mechanism. Nonces
// are single-use and short-lived; storing them in Store (rather than an
// in-process map, as internal/tsa's monotonicity guard uses) keeps nonce
// issuance/consumption correct under HA -- a client's new-nonce call and
// its follow-up request can land on different stateless replicas behind
// a load balancer, so the nonce has to be visible through the shared
// datastore, not held in one replica's memory. ACME account/order setup
// is comparatively low-frequency and not latency-sensitive (unlike
// /v1/tsa or /v1/ocsp), so the extra store round trip is an acceptable
// cost here -- see docs/design.md's Security section for the TSA
// monotonicity tradeoff this deliberately does not repeat.
type ACMENonceRepository interface {
	// Issue creates and returns a new, unused nonce expiring at
	// expiresAt.
	Issue(ctx context.Context, expiresAt time.Time) (string, error)
	// ConsumeIfValid atomically deletes nonce if it exists and hasn't
	// expired, returning whether it did (a JWS presenting an unknown,
	// expired, or already-consumed nonce is invalid, per RFC 8555
	// section 6.5.2).
	ConsumeIfValid(ctx context.Context, nonce string, now time.Time) (bool, error)
}

// ACMENonceBytes is the amount of CSPRNG entropy backend implementations
// of ACMENonceRepository.Issue generate per nonce (base64url-encoded).
// Declared once here, rather than duplicated as a local constant in
// internal/store/sqlite and internal/store/postgres, so the two can't
// drift if this is ever tuned.
const ACMENonceBytes = 24

// Store is the top-level datastore handle.
type Store interface {
	Ping(ctx context.Context) error
	Close() error
	Certificates() CertificateRepository
	Profiles() ProfileRepository
	Audit() AuditRepository
	ClientRoles() ClientRoleRepository
	ACMEEABTokens() ACMEEABTokenRepository
	ACMEAccounts() ACMEAccountRepository
	ACMEOrders() ACMEOrderRepository
	ACMENonces() ACMENonceRepository
	// WithExclusiveLock runs fn while holding a lock keyed by key, scoped
	// to this store's backend, blocking until it's acquired (or ctx is
	// done) -- for one-off actions (e.g. first-run CA bootstrap) that
	// must not run concurrently across multiple stateless replicas
	// sharing this store. SQLite is single-process by construction (see
	// sqlite.Open's SetMaxOpenConns(1)), so its implementation just calls
	// fn directly; Postgres backs it with a session-level advisory lock
	// (see postgres.WithAdvisoryLock). Callers must not type-assert the
	// concrete Store implementation to reach backend-specific locking --
	// that's exactly what this method exists to avoid.
	WithExclusiveLock(ctx context.Context, key int64, fn func() error) error
}

// ErrNotFound is returned by Get-style methods when no matching row exists.
var ErrNotFound = errNotFound{}

// ErrAlreadyRevoked is returned by CertificateRepository.Revoke when the
// target certificate was already revoked.
var ErrAlreadyRevoked = errAlreadyRevoked{}

// ErrAlreadyConsumed is returned by ACMEEABTokenRepository.MarkConsumed
// when the target token exists but was already consumed or has expired.
var ErrAlreadyConsumed = errAlreadyConsumed{}

// ErrAlreadyExists is returned by ACMEAccountRepository.Create when an
// account with the same JWK thumbprint was created concurrently, after
// the caller's own idempotency check found none.
var ErrAlreadyExists = errAlreadyExists{}

type errNotFound struct{}

func (errNotFound) Error() string { return "store: not found" }

type errAlreadyRevoked struct{}

func (errAlreadyRevoked) Error() string { return "store: certificate already revoked" }

type errAlreadyConsumed struct{}

func (errAlreadyConsumed) Error() string { return "store: eab token already consumed or expired" }

type errAlreadyExists struct{}

func (errAlreadyExists) Error() string { return "store: already exists" }
