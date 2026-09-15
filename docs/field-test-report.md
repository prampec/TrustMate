# TrustMate Field Test Report

- **Target**: `https://test.me:8182` (sandbox instance)
- **Date**: 2026-09-15
- **Method**: [Bruno](https://www.usebruno.com/) (`bru` CLI) driving the collection under
  [`docs/bruno/`](bruno/) for every REST call, `openssl` for everything Bruno can't do itself
  (CSR generation, binary OCSP/TSA request construction, and chain/signature verification of
  responses). The full, reproducible run is `docs/bruno/scripts/run-all.sh` — this report is
  that script's output folded into prose. See [`docs/bruno/README.md`](bruno/README.md) for how
  to re-run it.
- **Hostname note**: the sandbox this report was actually generated against is reachable on a
  different name/port than the one used throughout this document. Every command, URL, and
  extension value below has `test.me:8182` substituted in place of the real address, matching
  this repo's existing convention (`compose.yml`'s `TRUSTMATE_TLS_SANS`/`TRUSTMATE_PUBLIC_BASE_URL`
  default to `test.me`/`test.me:8182`) and the prior field test's target. Nothing else about the
  output is altered.
- **Version note**: `GET /healthz` and `GET /readyz` returned plain-text bodies (`ok` / `ready`),
  not the `{"status":"...","instance":"..."}` JSON `internal/api/router.go` produces as of the
  current `main` tip, and `GET /metrics` carries no `trustmate_instance_info` gauge. Both are
  introduced by the most recent commit on `main` (`8e0ec41`, which despite its "Review README.md"
  message also adds `TRUSTMATE_INSTANCE_NAME` support). Everything else tested below — Phase 3
  auth/RBAC/audit/clients and Phase 5 ACME routes/module toggle — is present and working, so the
  sandbox is running a build at or immediately after `3d383cd` ("Implement Phase 5"), one commit
  behind `main`. Worth confirming the sandbox gets rebuilt before relying on the instance-name
  feature specifically.
- **Admin material**: `work/admin.pem`, `work/admin-key.pem` and `work/chain.pem` were all present
  and valid this time (the prior report's `admin.pem`/`chain.pem`-empty issue is resolved).
  `work/chain.pem` bundles intermediate+root; `work/root.pem` alone is sufficient as a `--cacert`
  trust anchor since the server presents the intermediate in its TLS handshake.

## 1. Health / readiness / metrics

```sh
curl -sk https://test.me:8182/healthz    # 200, "ok"       (see Version note above)
curl -sk https://test.me:8182/readyz     # 200, "ready"
curl -sk https://test.me:8182/metrics    # 200, real Prometheus exposition text
```

`/metrics` is no longer the empty placeholder body the prior report found — Phase 3 wired it up
for real. After the run below (issuance, revocation, OCSP, TSA, both valid and error-path
requests), the counters reflect exactly the requests this report made:

```
trustmate_certificates_issued_total{profile="default"} 2
trustmate_certificates_issued_total{profile="document-signing"} 5
trustmate_certificates_issued_total{profile="tsa"} 2
trustmate_certificates_revoked_total 2
trustmate_ocsp_requests_total{status="bad_request"} 4
trustmate_ocsp_requests_total{status="ok"} 8
trustmate_tsa_requests_total{status="bad_request"} 7
trustmate_tsa_requests_total{status="ok"} 9
trustmate_store_up 1
```

(`profile="default"` counts the two `client-auth` certs minted via `POST /v1/clients` in §6 —
client onboarding reuses the leaf-issuance path under the hood.)

Bruno coverage: [`01-health/`](bruno/01-health/) (3 requests).

## 2. CA certificate distribution

Unchanged from the prior report: `GET /v1/ca/root.pem` and `GET /v1/ca/intermediate.pem` both
return `200`, no auth, valid PEM, and `openssl verify -CAfile root.pem intermediate.pem` still
says `OK`.

Bruno coverage: [`02-ca-distribution/`](bruno/02-ca-distribution/) (2 requests).

## 3. Authentication & RBAC (new since the last report)

This is the headline change. The prior report's top finding was that **every route was reachable
with no auth at all**. As of Phase 3, every route except the public PKI ones
(`/v1/ca/*.pem`, `/v1/crl/*`, `/v1/ocsp`, `/v1/tsa`) requires an mTLS client certificate carrying
a role (`admin` or `manager`) assigned in the `client_roles` table; `admin` is a strict superset
of `manager` (`roleSatisfies()`, `internal/api/auth.go`).

No client certificate at all:

```sh
curl -sk https://test.me:8182/v1/profiles
```
→ `401 {"error":"client certificate required"}`

A `manager`-role certificate (minted in §6 below) on a route that requires `admin`:

```sh
curl -sk --cert manager-client.pem --key manager-client-key.pem https://test.me:8182/v1/clients
```
→ `403 {"error":"insufficient role"}`

...but the same `manager` certificate succeeds on a `manager`-gated route (`GET /v1/profiles`,
`POST /v1/certificates`) — confirming the RBAC boundary runs both ways, not just "reject
everything without inspecting roles."

Bruno coverage: [`10-auth/`](bruno/10-auth/) — these three requests each need a different mTLS
identity (none / manager), which is why they're driven by three separate `bru run` invocations
with `--env-var certFile=...`/`certDomain=...` overrides rather than one recursive folder run;
see the folder's `docs {}` blocks and `scripts/run-all.sh`'s phase 4.

### 3.4 (carried forward, refined) Any authenticated manager can still issue against any profile

The prior report's other finding — the same CSR issuable against `document-signing`, `tsa`, and
`server-tls` alike — is **not** fully closed by Phase 3's RBAC work, just narrowed. Auth now
gates *whether* a caller can hit `POST /v1/certificates` at all, but not *which profile* they can
request once authenticated:

```sh
curl -sk -X POST https://test.me:8182/v1/certificates \
  --cert manager-client.pem --key manager-client-key.pem \
  -H "Content-Type: application/json" \
  -d '{"profile":"tsa","csr":"<CSR from a throwaway manager-role client>"}'
```
→ `201`, a cert with critical EKU = `id-kp-timeStamping`, signed by the intermediate CA — minted
by a client whose own role is just `manager`, the same role every other issuance caller holds.
`profiles.Lookup` still has no per-caller allow-list. Same practical recommendation as before:
worth closing before any deployment where "can issue *a* certificate" and "can issue *a
TSA/server-TLS-capable* certificate" need to be different privilege levels.

## 4. Certificate profiles

```sh
curl -sk --cert admin.pem --key admin-key.pem https://test.me:8182/v1/profiles   # manager+
```
→ `200`, four profiles: `default` (client-auth, used for API client onboarding), `document-signing`,
`server-tls`, `tsa` — each with resolved `key_usage`/`ext_key_usage`/`validity`/`enable_ocsp`/
`enable_crl`, matching `internal/profiles`' built-ins.

```sh
curl -sk -X POST --cert admin.pem --key admin-key.pem https://test.me:8182/v1/profiles/reload
```
→ `200 {"profiles":["default","document-signing","server-tls","tsa"]}` (admin-only;
`TRUSTMATE_PROFILES_DIR` isn't set on this sandbox, so the built-ins are all that come back) and
appends a `profiles-reload` audit entry (see §7).

Bruno coverage: [`03-profiles/`](bruno/03-profiles/) (2 requests).

## 5. Certificate issuance & lifecycle (`POST/GET/POST .../revoke`)

### 5.1 Happy path — `document-signing` profile

Same request shape as before, now requiring a `manager`(+) client cert:

```sh
curl -sk -X POST https://test.me:8182/v1/certificates \
  --cert admin.pem --key admin-key.pem \
  -H "Content-Type: application/json" \
  -d '{"profile":"document-signing","csr":"<PEM CSR, \n-escaped>"}'
```
→ `201`:
```json
{"serial":"527173366260447852108061547513862402823022597857",
 "profile":"document-signing",
 "not_before":"2026-09-15T09:15:58Z",
 "not_after":"2028-09-14T09:15:58Z",
 "pem":"-----BEGIN CERTIFICATE-----..."}
```

`openssl verify -CAfile root.pem -untrusted intermediate.pem leaf.pem` → `OK`. Extensions still
match the profile exactly (`KeyUsage: Digital Signature, Non Repudiation` critical,
`BasicConstraints: CA:FALSE` critical, AIA + CDP). One small correctness fix worth noting versus
the prior report: **AIA `caIssuers` now points at the *intermediate* cert**
(`.../v1/ca/intermediate.pem`), not the root — the prior report's build had this pointing at the
root for every leaf regardless of who actually issued it; `f43b27f` ("Fix CRL/OCSP to sign
per-issuer, not always as the intermediate") fixed the adjacent CRL/OCSP-signing half of the same
bug, and this AIA detail moved with it.

### 5.2 Lookup by serial — unchanged (`200` for a real serial, `404 {"error":"not found"}` for a
fabricated one).

### 5.3 Error handling — unchanged from the prior report (unknown profile, missing CSR, malformed
JSON, invalid CSR, wrong method all still return the same `400`/`405` shapes).

### 5.4 Revocation (new — there was no revoke endpoint at all in the prior report)

```sh
curl -sk -X POST https://test.me:8182/v1/certificates/{serial}/revoke \
  --cert admin.pem --key admin-key.pem \
  -H "Content-Type: application/json" -d '{"reason":"keyCompromise"}'
```
→ `200 {"serial":"...","revoked_at":"2026-09-15T09:12:33Z","reason":"keyCompromise"}`. Requires
`manager`(+); invalidates the cached CRL immediately (confirmed in §8 below — the very next CRL
fetch lists it, no 24h cache lag) and the cert shows `revoked` on the next OCSP query.

Re-revoking the same serial → `409 {"error":"already revoked"}`. Attempting to revoke the
intermediate CA's own serial (a non-leaf certificate) → `400 {"error":"only leaf certificates
can be revoked"}` — root/intermediate are structural anchors, deliberately not revocable through
this route.

Bruno coverage: [`05-certificates/`](bruno/05-certificates/) (12 requests: happy path, lookup,
not-found, four error cases, wrong method, plus a dedicated issue→revoke→re-revoke→revoke-non-leaf
sequence that feeds the OCSP "revoked" scenario in §8).

## 6. API client management (new)

Onboarding a new API caller is itself a REST call now, not a manual step:

```sh
curl -sk -X POST https://test.me:8182/v1/clients \
  --cert admin.pem --key admin-key.pem \
  -H "Content-Type: application/json" \
  -d '{"csr":"<PEM CSR>","role":"manager"}'
```
→ `201 {"serial":"...","role":"manager","pem":"-----BEGIN CERTIFICATE-----..."}` (admin-only).
Issues against the built-in `default`/client-auth profile and assigns the role in one step; if
role assignment somehow failed after issuance, the certificate is compensating-revoked rather
than left as an unauthorized-but-otherwise-valid identity (`assignRoleOrRevoke`,
`internal/api/certificates.go`) — not exercised here (nothing in this run triggers that failure
path), but worth knowing the guarantee exists.

```sh
curl -sk --cert admin.pem --key admin-key.pem https://test.me:8182/v1/clients
```
→ `200`, lists every client cert with its role, subject, and expiry:
```json
[{"serial":"172156355984668048271413993426781244319475125149","role":"admin",
  "subject":"CN=TrustMate Admin Access","not_after":"2027-09-15T08:39:06Z"},
 {"serial":"...","role":"manager","subject":"CN=fieldtest-manager-client,O=TrustMate Field Test",
  "not_after":"2027-09-15T09:14:11Z"}]
```

There's deliberately no separate "deactivate client" route — `POST
/v1/certificates/{serial}/revoke` on a client cert's own serial cuts off its API access too,
since `requireRole` checks `revoked_at` on every call.

Bruno coverage: [`04-clients/`](bruno/04-clients/) (2 requests) — the manager-role cert this
mints is reused for the RBAC boundary demo in §3.

## 7. Audit trail (new)

```sh
curl -sk --cert admin.pem --key admin-key.pem "https://test.me:8182/v1/audit?limit=20"
```
→ `200`, admin-only, newest first. A representative slice from this run (bootstrap entries at the
bottom, this report's activity above them):

| id | action | target (serial) | detail |
|---|---|---|---|
| 18 | `tsa-rotate` | new TSA serial | `previous: <old TSA serial>` |
| 17 | `revoke` | leaf serial | `keyCompromise` |
| 16 | `issue` | leaf serial | `document-signing` |
| 14 | `client-issue` | client serial | `manager` |
| 13 | `profiles-reload` | *(none)* | *(none)* |
| 5–1 | `issue` (actor `bootstrap`) | TSA / server-TLS / admin / intermediate / root | — |

Every mutating route in this report (`issue`, `revoke`, `client-issue`, `profiles-reload`,
`tsa-rotate`) writes exactly one audit entry, actor is the caller's `RemoteAddr` (or `bootstrap`
for first-run material) — a real, queryable record of who did what, which didn't exist at all in
the prior report.

Bruno coverage: [`06-audit/`](bruno/06-audit/) (1 request, run last so the entries above exist).

## 8. Revocation module (CRL + OCSP)

### 8.1 CRL

```sh
curl -sk https://test.me:8182/v1/crl/intermediate.crl
curl -sk https://test.me:8182/v1/crl/root.crl
curl -sk https://test.me:8182/v1/crl/intermediate     # 404, missing .crl suffix — unchanged
```

The prior report could only ever show an empty CRL ("no revoke endpoint yet"). This one isn't
empty:

```
Revoked Certificates:
    Serial Number: 7FC3CB78249277A4E0151920EA6C5FC8C0DA2A60
        Revocation Date: Sep 15 09:12:33 2026 GMT
        CRL entry extensions:
            X509v3 CRL Reason Code:
                Key Compromise
```

— the exact certificate revoked in §5.4, with the exact reason code requested, present
immediately (no cache lag, per `CRLBuilder.Invalidate()` on revoke).

### 8.2 OCSP

Three scenarios, all built and verified with `openssl ocsp`:

| Serial | Status | Notes |
|---|---|---|
| Issued, never revoked | `good` | `Responder Id: CN=TrustMate Intermediate CA`, signature verified OK |
| Issued, then revoked (§5.4) | **`revoked`**, `Revocation Time: Sep 15 09:12:33 2026 GMT` | **New** — unreachable in the prior report since nothing could be revoked yet |
| Never issued (fabricated serial) | `unknown` | Same as before — correct RFC 6960 behavior, distinct from `revoked` |

Error handling (`unsupported content type` for a wrong `Content-Type`, `invalid OCSP request` for
a malformed body) is unchanged from the prior report.

Bruno coverage: [`07-revocation/`](bruno/07-revocation/) (8 requests). The `good`/`revoked` OCSP
requests can't be pre-built like the third — they need the *actual* serial of a certificate
issued moments earlier in the same run, so `scripts/run-all.sh` extracts the issued PEM from the
§5 issuance responses and builds the DER requests with `openssl ocsp` before running this folder;
see [`docs/bruno/README.md`](bruno/README.md#why-some-fixtures-are-generated-not-committed).

## 9. TSA module (RFC 3161)

All of the prior report's coverage still holds unchanged: SHA-256/SHA-384 accepted, SHA-1
rejected (`400 {"error":"invalid timestamp request"}`), nonce echoed correctly, `-cert`
certReq embeds a chain that verifies to root, wrong `Content-Type`/malformed body both `400`.

### 9.1 Signing-key rotation (new)

```sh
curl -sk -X POST --cert admin.pem --key admin-key.pem https://test.me:8182/v1/tsa/rotate
```
→ `200`:
```json
{"serial":"<new TSA serial>","previous_serial":"<old TSA serial>","profile":"tsa",
 "not_before":"...","not_after":"...","pem":"-----BEGIN CERTIFICATE-----..."}
```
Admin-only. Hot-swaps the running responder to the new identity with no restart — confirmed by
immediately re-querying with `certReq=true` and checking the embedded signer chain still verifies
end to end:

```sh
openssl ts -query -data testfile.txt -sha256 -no_nonce -cert -out req.der
curl -sk -X POST --data-binary @req.der -H "Content-Type: application/timestamp-query" \
  https://test.me:8182/v1/tsa -o resp.der
openssl ts -verify -in resp.der -data testfile.txt -CAfile root.pem
```
→ `Verification: OK`, against the *new* identity. The previous TSA identity is left valid and
unrevoked (timestamps already issued under it remain verifiable), matching the documented design
in README.md.

Bruno coverage: [`08-tsa/`](bruno/08-tsa/) (8 requests, including rotation).

## 10. ACME enrollment (new, present but disabled on this sandbox)

`TRUSTMATE_ENABLE_ACME=false` on this deployment, so every `/v1/acme/*` route currently returns
Go's plain-text `404 page not found` (the module's routes are never registered — see
`internal/api/router.go`'s `if deps.ModuleConfig.EnableACME` guard) rather than the app's JSON
error envelope:

```sh
curl -sk https://test.me:8182/v1/acme/directory
curl -sk -X POST --cert admin.pem --key admin-key.pem \
  -d '{"role":"manager"}' https://test.me:8182/v1/acme/eab-tokens
```
→ both `404`. Not a bug — expected given the module toggle — but it means this report can't
exercise the enrollment flow described in README.md's "ACME enrollment" section (EAB-token issue
→ `new-account` → `new-order` → `finalize` → certificate download) on this particular sandbox.
Re-running `docs/bruno/09-acme/` against a deployment with `TRUSTMATE_ENABLE_ACME=true` would get
past the directory/EAB requests, but the full JWS-signed enrollment flow needs RFC 8555 request
signing that's out of scope for a static Bruno request body — worth a follow-up with a real ACME
client (`certbot`, `acme.sh`, or `lego`) against an ACME-enabled instance, not this report.

Bruno coverage: [`09-acme/`](bruno/09-acme/) (2 requests, kept as ready-made fixtures for a
future ACME-enabled run rather than deleted).

## 11. Protocol / routing edge cases

Unchanged from the prior report: plain HTTP to the HTTPS port still gets Go's
`Client sent an HTTP request to an HTTPS server.` (no plaintext fallback), wrong methods on
`/v1/ocsp`/`/v1/tsa` still `405`, and unknown routes still fall through to `ServeMux`'s plain-text
`404 page not found` rather than the app's JSON envelope.

## Observations

1. **Resolved: unauthenticated issuance.** The prior report's top finding — anyone reaching the
   listener could mint a cert claiming any capability — is closed. Every mutating route now
   requires an mTLS client certificate with a role; verified directly (§3).
2. **Still open, narrower: no per-caller profile allow-list.** A `manager`-role client can issue
   against `tsa`/`server-tls` just as freely as `document-signing` (§3.4). The privilege boundary
   RBAC added is "manager vs. admin vs. no cert," not "which profiles can this specific caller
   request." Worth closing if different callers should be scoped to different profiles.
3. **Resolved: CRL/OCSP could never show `revoked`.** Now demonstrated end to end — revoke via
   the API, see it in the CRL immediately (no cache lag) and in the next OCSP query (§8).
4. **New: real audit trail and `/metrics`.** Both were placeholders in the prior report; both now
   carry real, queryable data (§1, §7).
5. **New, minor: sandbox is one commit behind `main`.** `/healthz`/`/readyz` return plain text and
   `/metrics` has no `trustmate_instance_info` gauge, both introduced in the tip commit
   (`8e0ec41`). Everything else tested (Phase 3 + Phase 5 surface) is present, so the gap is one
   commit, not a stale major version — see the Version note at the top.
6. **Unchanged: TLS SAN is single-hostname only.** Still needed `curl -k` throughout; make sure
   `TRUSTMATE_TLS_SANS` covers every hostname a verifying client will actually use.
7. **Unchanged, minor: no TSA-cert-only download endpoint.** Still only reachable via `certReq`
   on a timestamp query; unaffected by rotation (§9.1) — a verifier that cached the *previous*
   TSA cert by serial can still fetch it via `GET /v1/certificates/{serial}`, just not via `/v1/ca/*`.
8. **New: ACME module is real but wasn't exercised.** Present in the router, off by default,
   off on this sandbox specifically — see §10 for what a follow-up run would need.
