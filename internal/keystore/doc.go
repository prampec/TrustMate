// Package keystore abstracts over where private keys live. The v1
// implementation is an encrypted file per key; the interface leaves a
// seam for PKCS#11 or a cloud KMS later without touching CA/TSA/
// revocation logic. See docs/design.md, module 5.
package keystore
