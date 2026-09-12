// Package revocation implements CRL generation and an RFC 6960 OCSP
// responder. Enable/disable via api.ModuleConfig.EnableRevocation — see
// docs/design.md, module 2.
//
// Phase 1 gaps, accepted per docs/design.md's roadmap (not oversights):
// no revoke endpoint exists yet, so the CRL is always empty and OCSP
// only distinguishes "good" from "unknown"; and /v1/ocsp has no rate
// limiting yet despite being public and unauthenticated.
package revocation
