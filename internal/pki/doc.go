// Package pki is the CA core: certificate issuance logic. It takes a
// profile, a subject, and a public key (or generates the keypair
// server-side) and produces a signed certificate. Always enabled — see
// docs/design.md, module 1.
package pki
