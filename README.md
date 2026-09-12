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
| `TRUSTMATE_PROFILES_DIR` | *(none)* | optional directory of extra profile definitions |

Health/ops endpoints: `GET /healthz`, `GET /readyz`, `GET /metrics` (all
served over HTTPS, like everything else).

CA/revocation/TSA endpoints (Phase 1-2; `POST /v1/certificates` has no
request-level auth yet — see `docs/design.md`'s Phase 3 entry):

| Endpoint | Purpose |
|---|---|
| `GET /v1/ca/root.pem` | root CA certificate (AIA `caIssuers` target) |
| `GET /v1/ca/intermediate.pem` | intermediate CA certificate (AIA `caIssuers` target) |
| `POST /v1/certificates` | issue a leaf certificate from a CSR against a named profile (`{"profile": ..., "csr": "<PEM>"}`) |
| `GET /v1/certificates/{serial}` | look up an issued certificate by serial |
| `GET /v1/crl/intermediate.crl` | intermediate CA's CRL (only when `TRUSTMATE_ENABLE_REVOCATION=true`) |
| `POST /v1/ocsp` | RFC 6960 OCSP responder (only when `TRUSTMATE_ENABLE_REVOCATION=true`) |
| `POST /v1/tsa` | RFC 3161 Time-Stamp Authority (only when `TRUSTMATE_ENABLE_TSA=true`) |

## Layout

```
cmd/trustmated/       service entrypoint
cmd/trustmate-admin/  operator CLI (not implemented yet — phase 3)
internal/api/         REST surface + health/metrics/logging
internal/bootstrap/   first-run CA/admin/server-tls/tsa cert generation
internal/config/      configuration loading (YAML file + env overrides)
internal/pki/         CA core: certificate issuance
internal/revocation/  CRL + OCSP responder
internal/tsa/         RFC 3161 Time-Stamp Authority, own bootstrap-issued signing identity
internal/profiles/    certificate profile definitions (config/code)
internal/keystore/    encrypted file-backed private key storage
internal/store/       issued-cert ledger, profiles, audit log (SQLite)
internal/observability/ structured logging setup
docs/design.md        full product design
```

## License

MIT — see [`LICENSE`](LICENSE).
