# Environment configuration

Full reference for every `TRUSTMATE_*` environment variable, organized by
subject. For the short list you need to get a first instance running, see
the [README](../README.md#quick-start) instead — this document is the
detailed reference behind it.

## Precedence

Configuration resolves in this order, each overriding the last:

1. **Defaults** (`internal/config.Defaults()`).
2. **Config file**, if `TRUSTMATE_CONFIG_FILE` points at a YAML file.
3. **Environment variables** — always win, including over the file.

A handful of settings (certificate validity periods) are YAML-file-only;
they're called out below where that applies. Everything else in this
document is an environment variable.

## Modularity: enabling and disabling features

TrustMate is built as independently-togglable modules. The CA/PKI core
(issuance, revocation ledger, client roster) is always on; three larger
subsystems are opt-in or opt-out via boolean env vars:

| Variable | Default | Effect when disabled |
|---|---|---|
| `TRUSTMATE_ENABLE_REVOCATION` | `true` | `/v1/crl/*` and `/v1/ocsp` routes are removed, and newly issued certificates stop carrying CDP/AIA-OCSP extensions |
| `TRUSTMATE_ENABLE_TSA` | `true` | `/v1/tsa` and `/v1/tsa/rotate` routes are removed; no TSA signing identity is bootstrapped on first run |
| `TRUSTMATE_ENABLE_ACME` | `false` | all `/v1/acme/*` routes (EAB issuance and the RFC 8555 client-facing routes) are removed |

Toggling one of these only changes route availability and certificate
extensions going forward — it does not retroactively revoke or reissue
anything already on disk. Flipping `TRUSTMATE_ENABLE_TSA` back on after a
run where it was off performs a fresh bootstrap of the TSA identity on
next start (bootstrap is idempotent per-module, not just globally).

## Server & networking

Required for anything beyond `localhost` development; the defaults only
make sense on a single dev machine.

| Variable | Default | Purpose |
|---|---|---|
| `TRUSTMATE_LISTEN_ADDR` | `:8080` | HTTPS listen address |
| `TRUSTMATE_TLS_SANS` | `localhost` | comma-separated SANs for the server TLS certificate — set this to the hostname(s) clients actually connect through |
| `TRUSTMATE_PUBLIC_BASE_URL` | `https://localhost:8080` | this deployment's externally reachable origin, templated into AIA/CDP/OCSP certificate extensions at issuance time — must be correct before you issue certificates that others will need to validate |

Changing `TRUSTMATE_TLS_SANS` or `TRUSTMATE_PUBLIC_BASE_URL` after the
server TLS certificate has already been bootstrapped does not reissue
it; it only affects extensions on certificates issued from that point
on. Regenerating the server TLS certificate itself means clearing its
keystore entry before restart.

## Logging

| Variable | Default | Purpose |
|---|---|---|
| `TRUSTMATE_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARN`, or `ERROR` |

## Instance name

*Optional.* `TRUSTMATE_INSTANCE_NAME` (default `TrustMate`) names this
deployment. It's the single knob behind two things:

- **Certificate identity.** On first run, `trustmated` bootstraps a root
  CA, intermediate CA, admin access certificate, server TLS certificate,
  and (if `TRUSTMATE_ENABLE_TSA=true`) a TSA signing certificate. Each
  one's Common Name is `"<instance name> <role>"` — e.g. an instance
  named `Example Corp` gets a root CA Common Name of
  `Example Corp Root CA`, an intermediate of `Example Corp Intermediate
  CA`, and so on through admin (`Admin Access`), server TLS (`REST API`),
  and TSA (`TSA`). There's no way to set one of these five independently
  — the instance name is the only override.

  This only takes effect on the run that performs bootstrap (i.e. before
  your keystore/datastore already has a root CA in it — see
  [Datastore & keystore](#datastore--keystore)). Changing
  `TRUSTMATE_INSTANCE_NAME` afterwards has no effect on already-issued
  certificates; there is no in-place rename.

- **Operator visibility.** The same name is surfaced wherever it's
  useful to tell one running instance apart from another (e.g. multiple
  named deployments, or replicas in an [HA/clustering](../README.md#haclustering)
  setup fronted by a shared load balancer):
  - logged at startup (`"trustmate starting"`, `"listening"`) and on
    every `logger.Info`/`Warn` bootstrap line where relevant;
  - in the JSON body of `GET /healthz` and `GET /readyz`
    (`{"status": "ok", "instance": "..."}`);
  - as the `trustmate_instance_info{instance="..."}` gauge (always `1`)
    on `GET /metrics` — the standard Prometheus "info metric" pattern,
    joinable against other `trustmate_*` series in PromQL.

Certificate **validity periods** for the same five identities
(`root_validity`, `intermediate_validity`, `admin_validity`,
`server_validity`, `tsa_validity`, each a Go duration string like
`8760h`) are config-file-only — set them under `bootstrap:` in the YAML
file pointed at by `TRUSTMATE_CONFIG_FILE`. There is no environment
variable for these; the defaults are 10y/5y/1y/1y/2y respectively.

## Datastore & keystore

The issued-certificate ledger and the private keys behind it are
configured separately, since they have different durability and
reachability requirements (see [HA/clustering](../README.md#haclustering)
for how the two interact).

### Datastore

*Optional to change* — `sqlite` is fine for a single instance.

| Variable | Default | Purpose |
|---|---|---|
| `TRUSTMATE_STORE_DRIVER` | `sqlite` | `sqlite` (single-process only) or `postgres` (required once you run more than one replica) |
| `TRUSTMATE_STORE_DSN` | `./data/trustmate.db` | sqlite file path, or a `postgres://...` connection string |

### Keystore

*Optional to change* — `file` (encrypted on local disk) is fine for a
single instance without an HSM/Vault available.

| Variable | Default | Purpose |
|---|---|---|
| `TRUSTMATE_KEYSTORE_DRIVER` | `file` | `file`, `vault`, or `pkcs11` |
| `TRUSTMATE_KEYSTORE_DIR` | `./data/keys` | encrypted private key storage directory (`file` driver only) |

#### `file` driver (default)

**Required** (this driver has no other way to get the passphrase):

| Variable | Purpose |
|---|---|
| `TRUSTMATE_KEK` | keystore encryption passphrase |
| `TRUSTMATE_KEK_FILE` | alternative to `TRUSTMATE_KEK` — path to a file (e.g. a mounted secret) containing the passphrase |

Set exactly one of the two; if both are set, the `_FILE` variant wins.

#### `vault` driver

Enable by setting `TRUSTMATE_KEYSTORE_DRIVER=vault`. Keys never leave
[Vault](https://developer.hashicorp.com/vault)'s Transit secrets engine;
every signature is a network round trip. This is the right choice for
HA/clustering, since it's reachable identically from every replica.

| Variable | Default | Purpose |
|---|---|---|
| `TRUSTMATE_VAULT_ADDR` | *(none)* | **required** — Vault address |
| `TRUSTMATE_VAULT_TRANSIT_MOUNT` | `transit` | Transit secrets engine mount path |
| `TRUSTMATE_VAULT_TOKEN` | *(none)* | **required** — Vault auth token |
| `TRUSTMATE_VAULT_TOKEN_FILE` | *(none)* | alternative to `TRUSTMATE_VAULT_TOKEN` — path to a mounted secret file |

#### `pkcs11` driver

Enable by setting `TRUSTMATE_KEYSTORE_DRIVER=pkcs11`. Only available in a
binary built with `-tags pkcs11` (see `Dockerfile.pkcs11`) — PKCS#11
needs cgo and `dlopen`-ing a vendor `.so` at runtime, which the default
`CGO_ENABLED=0` scratch build can't do. Works against a real HSM or
[SoftHSM2](https://www.opendnssec.org/softhsm/) for testing.

| Variable | Default | Purpose |
|---|---|---|
| `TRUSTMATE_PKCS11_MODULE_PATH` | *(none)* | **required** — path to the vendor's PKCS#11 `.so` |
| `TRUSTMATE_PKCS11_TOKEN_LABEL` | *(none)* | select the token by label (mutually exclusive with `TRUSTMATE_PKCS11_SLOT_NUMBER`) |
| `TRUSTMATE_PKCS11_SLOT_NUMBER` | *(none)* | select the token by slot number instead of label |
| `TRUSTMATE_PKCS11_PIN` | *(none)* | **required** — token PIN |
| `TRUSTMATE_PKCS11_PIN_FILE` | *(none)* | alternative to `TRUSTMATE_PKCS11_PIN` — path to a mounted secret file |

Set exactly one of `TRUSTMATE_PKCS11_TOKEN_LABEL` /
`TRUSTMATE_PKCS11_SLOT_NUMBER`.

## Bootstrap output

| Variable | Default | Purpose |
|---|---|---|
| `TRUSTMATE_BOOTSTRAP_OUTPUT_DIR` | `./data/bootstrap` | where first-run cert/key material (including the sensitive, unencrypted `admin-key.pem`) is written |

## Certificate profiles

*Optional.* Built-in profiles cover the default and `document-signing`
use cases; set this to load more without touching the binary.

| Variable | Default | Purpose |
|---|---|---|
| `TRUSTMATE_PROFILES_DIR` | *(none)* | directory of extra profile definitions (YAML), loaded alongside the built-ins; re-scanned on demand via `POST /v1/profiles/reload` |

## ACME enrollment

*Optional module* — see [Feature modules](#modularity-enabling-and-disabling-features)
to enable it (`TRUSTMATE_ENABLE_ACME=true`). Once enabled, there are no
additional environment variables: EAB credentials are issued at runtime
via `trustmate-admin acme issue-eab-token`, not configured up front. See
the [README](../README.md#acme-enrollment) for the enrollment flow.

## Operator CLI clients

`trustmate-admin` and `trustmate-management` are thin mTLS REST clients
(see `internal/cliclient`). These can be set as environment defaults for
their connection flags instead of passing `--server`/`--cert`/etc. on
every invocation:

| Variable | Default | Purpose |
|---|---|---|
| `TRUSTMATE_CLIENT_SERVER` | `https://localhost:8080` | TrustMate server base URL |
| `TRUSTMATE_CLIENT_CERT` | *(none)* | path to the client certificate PEM (mTLS identity) |
| `TRUSTMATE_CLIENT_KEY` | *(none)* | path to the client private key PEM |
| `TRUSTMATE_CLIENT_CA` | *(none)* | path to a CA bundle PEM to verify the server (defaults to the system trust store) |

`--cert`/`--key` (or their env equivalents) are required; there's no
default identity a CLI can use unattended.

## Pointing at a config file

| Variable | Default | Purpose |
|---|---|---|
| `TRUSTMATE_CONFIG_FILE` | *(none)* | path to a YAML config file, overlaid onto defaults before env vars are applied |

Use a config file for settings with no environment-variable equivalent
(currently: the `bootstrap:*_validity` durations); everything else in
this document can be set either way, with env taking precedence.
