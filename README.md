# TrustMate

A self-contained Certificate Authority service — CA issuance, CRL, OCSP
(RFC 6960), and RFC 3161 Time-Stamp Authority — in one REST-first,
dockerized, modular Go binary. No dependency on any other CA/TSA product,
only open-source libraries.

Status: **testing**. See [`docs/design.md`](docs/design.md) for
the full design, module breakdown, REST API sketch, and phased roadmap.

## Why

Issuing certificates, publishing CRLs, answering OCSP, and signing RFC
3161 tokens are each individually simple, well-specified operations. Most
existing CA products bundle them with a GUI-first admin plane built for
human operators. TrustMate is REST-first with no admin GUI, dockerized by
construction (a single static binary depending on nothing beyond the Go
runtime and OS libraries at build time), and modular — CA/revocation/TSA
are independently enabled or disabled via config.

## Quick start (development)

```sh
export TRUSTMATE_KEK=some-local-dev-passphrase   # encrypts the keystore at rest
go build ./...
go run ./cmd/trustmated
```

On first run, trustmated generates a root CA, an intermediate CA, an
admin REST access certificate, and the server's own TLS certificate (see
[`docs/design.md`](docs/design.md)'s Phase 0 entry). The root/intermediate/
server-tls private keys are kept encrypted at rest under the keystore
directory; the admin certificate and its **unencrypted** private key are
written once to the bootstrap output directory (`./data/bootstrap/` by
default) for the operator to retrieve and move off-host — `admin-key.pem`
is sensitive and not meant to stay there. Restarting with existing CA
material is a no-op (bootstrap is idempotent).

Environment variables (all optional; env always overrides a config file,
set via `TRUSTMATE_CONFIG_FILE`):

| Variable | Default | Purpose |
|---|---|---|
| `TRUSTMATE_CONFIG_FILE` | *(none)* | path to a YAML config file |
| `TRUSTMATE_LISTEN_ADDR` | `:8080` | HTTPS listen address |
| `TRUSTMATE_TLS_SANS` | `localhost` | comma-separated SANs for the server TLS certificate |
| `TRUSTMATE_PUBLIC_BASE_URL` | `https://localhost:8080` | this deployment's externally reachable origin, templated into AIA/CDP/OCSP certificate extensions at issuance time |
| `TRUSTMATE_LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARN`/`ERROR` |
| `TRUSTMATE_ENABLE_REVOCATION` | `true` | toggle CRL/OCSP module |
| `TRUSTMATE_ENABLE_TSA` | `true` | toggle RFC 3161 TSA module |
| `TRUSTMATE_ENABLE_ACME` | `false` | toggle RFC 8555 ACME enrollment module |
| `TRUSTMATE_STORE_DRIVER` | `sqlite` | `sqlite` or `postgres` — see [HA/clustering](#haclustering) |
| `TRUSTMATE_STORE_DSN` | `./data/trustmate.db` | datastore path (sqlite) or connection string (postgres) |
| `TRUSTMATE_KEYSTORE_DRIVER` | `file` | `file`, `vault`, or `pkcs11` (pkcs11 only in a `-tags pkcs11` build) — see [Pluggable keystores](#pluggable-keystores) |
| `TRUSTMATE_KEYSTORE_DIR` | `./data/keys` | encrypted private key storage directory (file driver) |
| `TRUSTMATE_KEK` | *(required for the file driver)* | keystore encryption passphrase (or use `TRUSTMATE_KEK_FILE` to read it from a mounted secret file) |
| `TRUSTMATE_VAULT_ADDR` | *(none)* | Vault address (vault driver) |
| `TRUSTMATE_VAULT_TRANSIT_MOUNT` | `transit` | Vault Transit secrets engine mount path (vault driver) |
| `TRUSTMATE_VAULT_TOKEN` | *(required for the vault driver)* | Vault auth token (or use `TRUSTMATE_VAULT_TOKEN_FILE`) |
| `TRUSTMATE_PKCS11_MODULE_PATH` | *(none)* | path to the vendor's PKCS#11 `.so` (pkcs11 driver) |
| `TRUSTMATE_PKCS11_TOKEN_LABEL` | *(none)* | PKCS#11 token label (pkcs11 driver; mutually exclusive with `TRUSTMATE_PKCS11_SLOT_NUMBER`) |
| `TRUSTMATE_PKCS11_SLOT_NUMBER` | *(none)* | select the PKCS#11 token by slot instead of label (pkcs11 driver) |
| `TRUSTMATE_PKCS11_PIN` | *(required for the pkcs11 driver)* | PKCS#11 token PIN (or use `TRUSTMATE_PKCS11_PIN_FILE`) |
| `TRUSTMATE_BOOTSTRAP_OUTPUT_DIR` | `./data/bootstrap` | where first-run cert/key material is written |
| `TRUSTMATE_PROFILES_DIR` | *(none)* | directory of extra profile definitions (YAML), loaded alongside the built-ins |

Health/ops endpoints: `GET /healthz`, `GET /readyz`, `GET /metrics` (real
Prometheus exposition text as of Phase 3; all served over HTTPS, like
everything else).

Every route below except the public PKI ones (`/v1/ca/*.pem`, `/v1/crl`,
`/v1/ocsp`, `/v1/tsa`) requires a client certificate presenting a role
assigned via `client_roles` — see `docs/design.md`'s Phase 3 entry. The
first such certificate is the bootstrap admin cert written to
`admin.pem`/`admin-key.pem` in the bootstrap output dir; use
`trustmate-admin clients add` to onboard more.

| Endpoint | Role | Purpose |
|---|---|---|
| `GET /v1/ca/root.pem` | none | root CA certificate (AIA `caIssuers` target) |
| `GET /v1/ca/intermediate.pem` | none | intermediate CA certificate (AIA `caIssuers` target) |
| `POST /v1/certificates` | manager | issue a leaf certificate from a CSR against a named profile (`{"profile": ..., "csr": "<PEM>"}`) |
| `GET /v1/certificates/{serial}` | manager | look up an issued certificate by serial |
| `POST /v1/certificates/{serial}/revoke` | manager | revoke a certificate (`{"reason": "keyCompromise"}`, optional) |
| `GET /v1/profiles` | manager | list built-in and config-loaded certificate profiles |
| `POST /v1/profiles/reload` | admin | re-scan `TRUSTMATE_PROFILES_DIR` without a restart |
| `POST /v1/clients` | admin | issue a new API client certificate and assign it a role |
| `GET /v1/clients` | admin | list API client certificates and their roles |
| `GET /v1/audit` | admin | issuance/revocation/config-change audit trail (`?limit=N`) |
| `GET /v1/crl/intermediate.crl` | none | intermediate CA's CRL, lists revoked leaf certificates (only when `TRUSTMATE_ENABLE_REVOCATION=true`) |
| `GET /v1/crl/root.crl` | none | root CA's CRL, lists a revoked intermediate certificate; this is what the intermediate cert's own CDP points at (only when `TRUSTMATE_ENABLE_REVOCATION=true`) |
| `POST /v1/ocsp` | none | RFC 6960 OCSP responder (only when `TRUSTMATE_ENABLE_REVOCATION=true`) |
| `POST /v1/tsa` | none | RFC 3161 Time-Stamp Authority (only when `TRUSTMATE_ENABLE_TSA=true`) |
| `POST /v1/tsa/rotate` | admin | mint a new TSA signing identity and hot-swap to it immediately (only when `TRUSTMATE_ENABLE_TSA=true`) |
| `POST /v1/acme/eab-tokens` | admin | issue a one-time External Account Binding credential to start ACME enrollment (only when `TRUSTMATE_ENABLE_ACME=true`) |
| `GET /v1/acme/directory`, `/new-nonce`, `/order/{id}`, `/authorization/{id}`, `/certificate/{id}` | none | RFC 8555 client-facing routes, authenticated by JWS (not mTLS) — see below |
| `POST /v1/acme/new-account`, `/new-order`, `/order/{id}/finalize` | none | same — request bodies carry their own JWS signature |

Note: the built-in `tsa` profile sets neither `enable_crl` nor
`enable_ocsp`, so a TSA certificate carries no CDP/AIA-OCSP extension —
this predates rotation and isn't something it changes. Revoking a TSA
identity you suspect is compromised (`POST
/v1/certificates/{serial}/revoke`) updates the ledger and audit trail,
but isn't independently discoverable by a relying party from the
certificate itself; it's not a complete mitigation on its own.

## ACME enrollment

TrustMate's certificates are role-bound API-access client certs, not
domain-validated web certs, so `/v1/acme/*` (RFC 8555, off by default —
`TRUSTMATE_ENABLE_ACME=true`) authorizes enrollment via [External Account
Binding](https://www.rfc-editor.org/rfc/rfc8555#section-7.3.4) instead of
http-01/dns-01 challenges: an admin issues a one-time HMAC credential
(`trustmate-admin acme issue-eab-token --role=manager`), and an ACME
client uses it once, during `new-account`, to bind its own key to that
role. From there it's a standard `new-account` → `new-order` → `finalize`
→ certificate-download flow with no challenges to complete — see
`docs/design.md`'s module 10 entry for the exact deviations from strict
RFC 8555 conformance this implies.

## Pluggable keystores

Private keys live behind the `keystore.KeyStore` interface
(`internal/keystore`), selected via `TRUSTMATE_KEYSTORE_DRIVER`:

- `file` (default): AES-256-GCM-encrypted file per key, passphrase via
  `TRUSTMATE_KEK`/`TRUSTMATE_KEK_FILE`.
- `vault`: [HashiCorp Vault](https://developer.hashicorp.com/vault)'s
  Transit secrets engine — keys never leave Vault; every signature is a
  network round trip. The right choice for HA/clustering (see below),
  since it's reachable identically from every replica.
- `pkcs11`: a real HSM or [SoftHSM2](https://www.opendnssec.org/softhsm/)
  for testing. Only available in a binary built with `-tags pkcs11` (see
  `Dockerfile.pkcs11`) — PKCS#11 needs cgo and `dlopen`-ing a vendor
  `.so` at runtime, which the default `CGO_ENABLED=0` scratch build
  can't do.

## HA/clustering

Running multiple stateless `trustmated` replicas behind a load balancer
needs:

- `TRUSTMATE_STORE_DRIVER=postgres` — SQLite is intentionally
  single-process (see `internal/store/sqlite`), so a shared Postgres is
  required once there's more than one replica.
- `TRUSTMATE_KEYSTORE_DRIVER=vault` (or `pkcs11` against a shared HSM) —
  the `file` keystore isn't reachable identically from every replica.

First-run CA bootstrap is safe under this: `cmd/trustmated` serializes it
behind a Postgres advisory lock when `store.driver` is `postgres`, so
concurrent replicas starting against a fresh database don't race to each
generate their own root CA. See `docs/design.md`'s "HA / clustering
considerations" section for what does (and deliberately doesn't) get
coordinated across replicas — e.g. RFC 3161 TSA's monotonic-timestamp
guard stays per-replica, a documented tradeoff, not a gap.

## Operator CLIs

`trustmate-admin` and `trustmate-management` are thin mTLS REST clients
over the endpoints above (see `internal/cliclient`). Connection flags
(`--server`, `--cert`, `--key`, `--ca`) default from
`TRUSTMATE_CLIENT_{SERVER,CERT,KEY,CA}`.

```sh
trustmate-admin profiles list
trustmate-admin profiles reload
trustmate-admin clients add --csr=new-client.csr --role=manager
trustmate-admin clients list
trustmate-admin audit list --limit=50
trustmate-admin acme issue-eab-token --role=manager

trustmate-management certificates issue --profile=document-signing --csr=leaf.csr
trustmate-management certificates get <serial>
trustmate-management certificates revoke <serial> --reason=keyCompromise
trustmate-management tsa rotate
```

`tsa rotate` mints a new TSA signing identity and switches the running
server to it immediately — no restart needed, and the change is
restart-safe (a later restart picks up the same identity). The previous
identity is left valid and unrevoked so timestamps already issued under
it remain verifiable.

Intermediate and root CA key rotation remain out of scope: rotating those
safely means resolving CRL/OCSP per-certificate by issuer generation, not
just minting a new key — a bigger architecture change than TSA rotation
needed, since a TSA cert only ever signs new timestamps.

## Layout

```
cmd/trustmated/          service entrypoint
cmd/trustmate-admin/     operator CLI: profiles, client roster, audit
cmd/trustmate-management/ operator CLI: certificate issue/get/revoke
internal/api/            REST surface + RBAC + health/metrics/logging
internal/acme/           RFC 8555 JWS/JWK primitives (parsing, verification, thumbprints)
internal/bootstrap/      first-run CA/admin/server-tls/tsa cert generation
internal/cliclient/      shared mTLS REST client for both operator CLIs
internal/config/         configuration loading (YAML file + env overrides)
internal/pki/            CA core: certificate issuance
internal/revocation/     CRL + OCSP responder
internal/tsa/            RFC 3161 Time-Stamp Authority, own bootstrap-issued signing identity
internal/profiles/       certificate profile definitions (built-in + config-loaded registry)
internal/keystore/       pluggable private key storage: file (default), vault, pkcs11
internal/store/          issued-cert ledger, profiles, roles, audit log, ACME state (sqlite, postgres)
internal/observability/  structured logging + Prometheus metrics
docs/design.md           full product design
Dockerfile.pkcs11        opt-in cgo build variant for the pkcs11 keystore driver
```

## License

MIT — see [`LICENSE`](LICENSE).
