---
name: trustmate
description: Operate a TrustMate certificate authority with the trustmate MCP tools. Covers issuing, previewing, inspecting and revoking X.509 certificates, checking revocation via CRL, onboarding API clients and requesting RFC 3161 timestamps. Use when the user asks for a certificate, a TLS or signing cert, a cert's status or expiry, to revoke a cert, to add an API client, or to timestamp a file against TrustMate.
---

# Operating TrustMate

TrustMate is a certificate authority. The `trustmate` MCP server reaches it
with the user's mTLS client certificate. That certificate's role limits what
you can do:

- **manager**: list profiles, preview, issue, look up and revoke certificates.
- **admin**: everything a manager can do, plus clients, audit, profile reload
  and TSA rotation.

If a tool is missing, the server is probably in read-only mode. Tell the user
to turn off the plugin's "Read-only mode" option. Don't try to work around it.

## Rules

- **Profiles decide the certificate.** Key usage, EKU, validity and the
  AIA/OCSP/CRL URLs come from the profile, never from the CSR. Call
  `list_profiles` and choose the profile by its key usages, not by its name
  alone. Ask the user when more than one could fit.
- **Preview before issuing.** Call `preview_certificate` with the same inputs
  you will pass to `issue_certificate`. Show the user the subject, validity
  and key usages, and issue only after they agree.
- **Confirm destructive actions.** Get explicit confirmation before
  `revoke_certificate`, `issue_client_certificate` and `rotate_tsa`.
  Revocation is permanent. Revoking an API client's certificate also cuts off
  that client's access.
- **Never handle private keys.** `issue_certificate` generates the key
  locally and returns only file paths. Don't read, print or move key files.
  Never ask the user to paste a key.
- **Serials are decimal strings**, for example `"123456789"`. Don't convert
  them to hex.

## Reading errors

Errors carry an RFC 9457 problem document. Branch on its `type`, then use
its extension members instead of guessing:

| `type` (after `urn:trustmate:problem:`) | What to do |
|---|---|
| `unknown-profile` | choose from `available_profiles` |
| `missing-field` | supply `missing_fields` |
| `invalid-role`, `unknown-revocation-reason` | choose from `allowed_values` |
| `insufficient-role` | the certificate's `role` is below `required_role`; tell the user, don't retry |
| `client-certificate-revoked`, `client-certificate-not-authorized` | the plugin's client certificate can't be used; the user must configure another |
| `invalid-csr` | the CSR is malformed or its signature is invalid; regenerate it |
| `already-revoked` | nothing to do; report it |
| `not-found` | check the serial |

A plain-text 404 means the server has that module (revocation, TSA, ACME)
turned off.

## Common tasks

- **Status of a certificate:** `get_certificate`. Report subject, profile,
  validity, days remaining and revocation state. Cross-check with `get_crl`
  (`ca: intermediate`) when the revocation module is on.
- **Certificate for a host:** pick the profile, then `preview_certificate`
  with `common_name` and `dns_names` set to the hostname. Confirm, then
  `issue_certificate` with a short `name`. Report the serial and the two file
  paths.
- **Signing an existing CSR:** pass `csr_pem` and leave `common_name`,
  `dns_names` and `key_type` empty.
- **Timestamp a file:** `timestamp_file`. Only the file's SHA-256 leaves the
  machine. The token is written to `<name>.tsr`.
- **Verify locally:** the `trustmate://ca/root.pem` and
  `trustmate://ca/intermediate.pem` resources hold the chain, e.g. for
  `openssl verify -CAfile root.pem -untrusted intermediate.pem cert.pem`.

The full API, with each route's required role and the error catalogue, is the
`trustmate://openapi.yaml` resource.
