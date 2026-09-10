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
go build ./...
go run ./cmd/trustmated
```

Environment variables (all optional):

| Variable | Default | Purpose |
|---|---|---|
| `TRUSTMATE_LISTEN_ADDR` | `:8080` | HTTP listen address |
| `TRUSTMATE_LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARN`/`ERROR` |
| `TRUSTMATE_ENABLE_REVOCATION` | `true` | toggle CRL/OCSP module |
| `TRUSTMATE_ENABLE_TSA` | `true` | toggle RFC 3161 TSA module |

Health/ops endpoints: `GET /healthz`, `GET /readyz`, `GET /metrics`.

## Layout

```
cmd/trustmated/       service entrypoint
cmd/trustmate-admin/  operator CLI (not implemented yet — phase 3)
internal/api/         REST surface + health/metrics/logging
internal/pki/         CA core: certificate issuance
internal/revocation/  CRL + OCSP responder
internal/tsa/         RFC 3161 Time-Stamp Authority
internal/profiles/    certificate profile definitions (config/code)
internal/keystore/    private key storage abstraction
internal/store/       issued-cert ledger, serials, revocations, audit log
internal/observability/ structured logging setup
docs/design.md        full product design
```

## License

MIT — see [`LICENSE`](LICENSE).
