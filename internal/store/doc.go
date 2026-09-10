// Package store is the issued-certificate ledger: serial number
// allocation, revocation records, and the audit log, behind an interface
// so a Postgres implementation can sit alongside the SQLite default
// without touching call sites. See docs/design.md, module 6.
package store
