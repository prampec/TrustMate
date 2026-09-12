# TrustMate Field Test Report

- **Target**: `https://test.me:8182` (sandbox instance, current git `main` @ `0c3d471`)
- **Date**: 2026-09-12
- **Method**: `curl` + `openssl` against the live REST API, no auth (none is implemented yet per `docs/design.md` Phase 3)
- **Note on admin material**: `work/admin-key.pem` was present and valid; `work/admin.pem` and `work/chain.pem` were empty (0 bytes) in the downloaded bundle. This turned out not to block testing — `POST /v1/certificates` and every other route are currently unauthenticated, so the admin identity wasn't needed for anything below. Worth re-downloading `admin.pem`/`chain.pem` before they're needed for something that does check them.

All commands below assume `BASE=https://test.me:8182` and use `-k` because the server's TLS cert only carries `DNS:localhost` as a SAN (see [Observations](#observations)).

## 1. Health / readiness / metrics

```sh
curl -sk https://test.me:8182/healthz
curl -sk https://test.me:8182/readyz
curl -sk https://test.me:8182/metrics
```

| Endpoint | Result |
|---|---|
| `GET /healthz` | `200`, body `ok` |
| `GET /readyz` | `200`, body `ready` |
| `GET /metrics` | `200`, empty body (placeholder exposition format, matches code comment — not implemented yet) |

## 2. CA certificate distribution

```sh
curl -sk https://test.me:8182/v1/ca/root.pem
curl -sk https://test.me:8182/v1/ca/intermediate.pem
```

Both returned `200` with `Content-Type: application/x-pem-file` and valid PEM certs:

- Root: `CN=TrustMate Root CA`, self-signed, 10y validity, `CA:TRUE` critical, no pathlen restriction issue.
- Intermediate: `CN=TrustMate Intermediate CA`, issued by root, 5y validity, carries AIA (OCSP + caIssuers) and CDP pointing back at `https://test.me:8182/...`.

```sh
openssl verify -CAfile root.pem intermediate.pem
```
→ `intermediate.pem: OK`

## 3. Certificate issuance (`POST /v1/certificates`)

### 3.1 Happy path — `document-signing` profile

```sh
openssl ecparam -name prime256v1 -genkey -noout -out leaf-key.pem
openssl req -new -key leaf-key.pem \
  -subj "/CN=fieldtest-signer/O=TrustMate Field Test" -out leaf.csr

curl -sk -X POST https://test.me:8182/v1/certificates \
  -H "Content-Type: application/json" \
  -d '{"profile":"document-signing","csr":"<PEM CSR, \n-escaped>"}'
```

→ `201 Created`:
```json
{"serial":"247437505557170842580054839604061872182202646698",
 "profile":"document-signing",
 "not_before":"2026-09-12T13:39:29Z",
 "not_after":"2028-09-11T13:39:29Z",
 "pem":"-----BEGIN CERTIFICATE-----..."}
```

Verified the returned cert:

```sh
openssl verify -CAfile root.pem -untrusted intermediate.pem leaf.pem   # → leaf.pem: OK
openssl x509 -in leaf.pem -noout -text
```

Extensions matched the `document-signing` profile exactly: `KeyUsage: Digital Signature, Non Repudiation` (critical), `BasicConstraints: CA:FALSE` (critical), AIA (`OCSP` + `caIssuers`) and CRL Distribution Point both pointing at the public base URL — confirms `Profile.WithIssuerURLs` templating works end-to-end against a real deployment.

### 3.2 Lookup by serial

```sh
curl -sk https://test.me:8182/v1/certificates/247437505557170842580054839604061872182202646698
```
→ `200`, full record (serial/kind/profile/subject/issuer_serial/validity/PEM) matches the issuance response.

```sh
curl -sk https://test.me:8182/v1/certificates/999999999999999999999999999999999999
```
→ `404`, `{"error":"not found"}`

### 3.3 Error handling

| Case | Request | Result |
|---|---|---|
| Unknown profile | `{"profile":"not-a-real-profile","csr":"bogus"}` | `400 {"error":"unknown profile"}` |
| Missing `csr` | `{"profile":"document-signing"}` | `400 {"error":"profile and csr are required"}` |
| Malformed JSON | `{not json` | `400 {"error":"malformed JSON body"}` |
| Invalid CSR (garbage PEM) | `{"profile":"document-signing","csr":"...garbage..."}` | `400`, `{"error":"invalid CSR: pki: parsing CSR: asn1: structure error..."}` — full Go ASN.1 parser error is echoed back to the client |
| Wrong HTTP method | `GET /v1/certificates` | `405 Method Not Allowed` |

### 3.4 Security-relevant finding: any profile is issuable, unauthenticated

Since `POST /v1/certificates` performs no auth and no server-side check on which profiles a given caller may request, the **same CSR was successfully issued against the `tsa` and `server-tls` profiles** — not just `document-signing`:

```sh
curl -sk -X POST https://test.me:8182/v1/certificates \
  -H "Content-Type: application/json" \
  -d '{"profile":"tsa","csr":"<same CSR>"}'
# → 201, cert with critical EKU = id-kp-timeStamping only, signed by the intermediate CA

curl -sk -X POST https://test.me:8182/v1/certificates \
  -H "Content-Type: application/json" \
  -d '{"profile":"server-tls","csr":"<same CSR>"}'
# → 201, cert with EKU = serverAuth, signed by the intermediate CA
```

This is expected given the documented Phase-1 state ("no request-level auth yet... anyone who can reach the listener can issue a certificate" — `internal/api/certificates.go`), but it's worth flagging explicitly: today, any network-reachable caller can mint a cert chaining to this CA claiming **server TLS** or **TSA** capability, not just document-signing, since `profiles.Lookup` has no allow-list per caller. This should be closed by Phase 3's auth work (or, sooner, by restricting which profiles are reachable via the public issuance route vs. reserved for bootstrap-only use).

## 4. Revocation module

### 4.1 CRL

```sh
curl -sk https://test.me:8182/v1/crl/intermediate.crl
openssl crl -inform DER -in intermediate.crl -noout -text
```
→ `200`, `Content-Type: application/pkix-crl`, valid CRL signed by the intermediate CA, "No Revoked Certificates" (there is currently no revoke endpoint anywhere in the API, so this is expected to always be empty in this build).

```sh
curl -sk https://test.me:8182/v1/crl/root.crl        # → 404 {"error":"not found"}
curl -sk https://test.me:8182/v1/crl/intermediate    # → 404 {"error":"not found"} (missing .crl suffix)
```

### 4.2 OCSP

Built a real OCSP request against the leaf cert issued in §3.1:

```sh
openssl ocsp -issuer intermediate.pem -cert leaf.pem -reqout ocsp-req.der -no_nonce
curl -sk -X POST https://test.me:8182/v1/ocsp \
  -H "Content-Type: application/ocsp-request" --data-binary @ocsp-req.der -o ocsp-resp.der
openssl ocsp -issuer intermediate.pem -cert leaf.pem -respin ocsp-resp.der -text -no_nonce
```
→ `200`, `Content-Type: application/ocsp-response`; response signature verified OK; `Cert Status: good`, `Responder Id: CN=TrustMate Intermediate CA`.

Fabricated a request for a serial that was never issued:
```sh
openssl ocsp -issuer intermediate.pem -serial 0x1234...5678 -reqout ocsp-req-unknown.der -no_nonce
curl -sk -X POST .../v1/ocsp ... --data-binary @ocsp-req-unknown.der
```
→ `200`, `Cert Status: unknown` — correct RFC 6960 behavior (distinct from "revoked", which isn't reachable in this build since nothing can be revoked yet).

Error handling:

| Case | Result |
|---|---|
| Wrong `Content-Type` (`text/plain`) | `400 {"error":"unsupported content type"}` |
| Malformed body (`"not a real ocsp request"`) | `400 {"error":"invalid OCSP request"}` |

## 5. TSA module (RFC 3161)

```sh
echo "test document contents for timestamping" > testfile.txt
openssl ts -query -data testfile.txt -sha256 -no_nonce -out ts-req.der
curl -sk -X POST https://test.me:8182/v1/tsa \
  -H "Content-Type: application/timestamp-query" --data-binary @ts-req.der -o ts-resp.der
openssl ts -reply -in ts-resp.der -text
```
→ `200`, `Content-Type: application/timestamp-reply`, `Status: Granted`, `TSA: DirName:/CN=TrustMate TSA`, correct hash echoed back.

**Chain verification**, requesting the signer cert be embedded (`-cert`):
```sh
openssl ts -query -data testfile.txt -sha256 -no_nonce -cert -out ts-req-cert.der
curl -sk -X POST .../v1/tsa ... --data-binary @ts-req-cert.der -o ts-resp-cert.der
openssl ts -verify -in ts-resp-cert.der -data testfile.txt -CAfile root.pem
```
→ **`Verification: OK`** — confirms the dedicated TSA signing identity (own leaf cert, `CN=TrustMate TSA`, issued by the intermediate CA, critical EKU = `id-kp-timeStamping` only) chains correctly to root, and `AddTSACertificate`/embedding logic in `internal/tsa/responder.go` works as designed.

Without `-cert` in the query, the response doesn't embed the signer chain (by RFC 3161 design — certReq is opt-in), so a verifier needs the TSA cert from elsewhere; there's currently no `GET` endpoint to fetch the TSA leaf cert directly (only root/intermediate are exposed under `/v1/ca/`). Not a bug, just a gap if API consumers want to cache/pin the TSA cert without asking for certReq on every query.

Nonce handling:
```sh
openssl ts -query -data testfile.txt -sha256 -out ts-req-nonce.der   # nonce included by default
curl -sk -X POST .../v1/tsa ... --data-binary @ts-req-nonce.der -o ts-resp-nonce.der
openssl ts -reply -in ts-resp-nonce.der -text | grep -i nonce
```
→ nonce `0xE8EF780E7C3A14C1` sent, same nonce echoed back correctly.

Hash algorithm handling:

| Case | Result |
|---|---|
| SHA-256 query | `200`, granted |
| SHA-384 query | `200`, granted, `Hash Algorithm: sha384` |
| **SHA-1 query** | `400 {"error":"invalid timestamp request"}` — correctly rejected per `internal/tsa/responder.go`'s explicit SHA-1 ban |
| Wrong `Content-Type` (`text/plain`) | `400 {"error":"unsupported content type"}` |
| Malformed body (`"garbage"`) | `400 {"error":"invalid timestamp request"}` |

## 6. Protocol / routing edge cases

| Case | Result |
|---|---|
| Plain HTTP request to the HTTPS port | `400`, body: `Client sent an HTTP request to an HTTPS server.` (Go's TLS listener default — no plaintext fallback) |
| `GET /v1/ocsp`, `GET /v1/tsa` (wrong method) | `405 Method Not Allowed` |
| `GET /v1/nonexistent` | `404 page not found` (Go `ServeMux` default; note this is a plain-text 404, not the app's `{"error":...}` JSON envelope, since it never reaches app code) |

## Observations

1. **Unauthenticated issuance covers all profiles, not just `document-signing`** — see §3.4. Flagged as the most actionable finding; matches the documented Phase-3 roadmap but is worth confirming is closed before this leaves sandbox status.
2. **Server TLS SAN is `localhost` only** (`TRUSTMATE_TLS_SANS=localhost` in `compose.yml`), so every request against `test.me` needed `curl -k` / `openssl ... ` without hostname verification. Fine for a sandbox, but `TRUSTMATE_TLS_SANS` should include the real hostname before this is used by any client that verifies certs (which should be everyone, eventually).
3. **CRL is structurally correct but permanently empty** — there's no revoke endpoint yet in this build, so CRL/OCSP can only ever report "good" or "unknown," never "revoked." Expected for Phase 1/2 scope.
4. **No TSA-cert-only download endpoint** — only root/intermediate are exposed via `/v1/ca/`; the TSA signing cert is only obtainable by requesting `certReq=true` on a timestamp query. Minor UX gap for verifiers that want to pin/cache it separately.
5. Downloaded admin bootstrap bundle (`work/admin.pem`, `work/chain.pem`) came through empty — re-pull these before they're actually needed (they aren't yet, since issuance has no auth).
