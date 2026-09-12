# TrustMate

A self-contained Certificate Authority service — CA issuance, CRL, OCSP
(RFC 6960), and RFC 3161 Time-Stamp Authority — in one REST-first,
dockerized, modular Go binary. No dependency on any other CA/TSA product,
only open-source libraries.

Status: **early development.** See [`docs/design.md`](docs/design.md) for
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
| `TRUSTMATE_STORE_DSN` | `./data/trustmate.db` | SQLite datastore path |
| `TRUSTMATE_KEYSTORE_DIR` | `./data/keys` | encrypted private key storage directory |
| `TRUSTMATE_BOOTSTRAP_OUTPUT_DIR` | `./data/bootstrap` | where first-run cert/key material is written |
| `TRUSTMATE_KEK` | *(required)* | keystore encryption passphrase (or use `TRUSTMATE_KEK_FILE` to read it from a mounted secret file) |
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
| `GET /v1/crl/intermediate.crl` | none | intermediate CA's CRL (only when `TRUSTMATE_ENABLE_REVOCATION=true`) |
| `POST /v1/ocsp` | none | RFC 6960 OCSP responder (only when `TRUSTMATE_ENABLE_REVOCATION=true`) |
| `POST /v1/tsa` | none | RFC 3161 Time-Stamp Authority (only when `TRUSTMATE_ENABLE_TSA=true`) |
| `POST /v1/tsa/rotate` | admin | mint a new TSA signing identity and hot-swap to it immediately (only when `TRUSTMATE_ENABLE_TSA=true`) |

Note: the built-in `tsa` profile sets neither `enable_crl` nor
`enable_ocsp`, so a TSA certificate carries no CDP/AIA-OCSP extension —
this predates rotation and isn't something it changes. Revoking a TSA
identity you suspect is compromised (`POST
/v1/certificates/{serial}/revoke`) updates the ledger and audit trail,
but isn't independently discoverable by a relying party from the
certificate itself; it's not a complete mitigation on its own.

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
internal/bootstrap/      first-run CA/admin/server-tls/tsa cert generation
internal/cliclient/      shared mTLS REST client for both operator CLIs
internal/config/         configuration loading (YAML file + env overrides)
internal/pki/            CA core: certificate issuance
internal/revocation/     CRL + OCSP responder
internal/tsa/            RFC 3161 Time-Stamp Authority, own bootstrap-issued signing identity
internal/profiles/       certificate profile definitions (built-in + config-loaded registry)
internal/keystore/       encrypted file-backed private key storage
internal/store/          issued-cert ledger, profiles, client roles, audit log (SQLite)
internal/observability/  structured logging + Prometheus metrics
docs/design.md           full product design
```

## License

MIT — see [`LICENSE`](LICENSE).
