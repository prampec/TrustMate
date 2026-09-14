# TrustMate — a self-contained CA + TSA service (product design)

Status: idea / early setup. The idea of creating a product like this came from working with
EJBCA + SignServer, and step-ca. While these solutions are great
it is hard to automate tasks with them (e.g. performing agentic tooling).

## Motivation

The original need was a test a PKI for an application requires trust a provider for testing.

Experiences with other solutions:

- **step-ca** (tried first) is REST-native and
  container-friendly, but templates are hard to maintain and has no RFC 3161 Time-Stamp Authority
- **EJBCA + SignServer** together
  cover CA + OCSP + CRL + TSA, but both are GUI-administered products with
  automation as an afterthought: no CLI to edit certificate profile fields
  fragile CLI-path discovery inside the container images, two databases,
  two admin planes, and documented version drift in GUI workflows.

None of this complexity is inherent to the *problem* — issuing certificates,
publishing CRLs, answering OCSP, and signing RFC 3161 tokens are each
individually simple, well-specified operations. It's inherent to reusing
products built for general-purpose enterprise PKI administration by human
operators, when what we actually want is a small, deterministic, scriptable
service.

**TrustMate** generalizes that idea beyond just a test
environment: a self-contained CA/OCSP/TSA service — no dependency on any
other CA/TSA product, only open-source *libraries* — that is REST-first,
has no admin GUI, is containerized by construction (a single closed-scope
binary with no external service dependencies beyond its own datastore),
and is architected from day one to be run as a real production service, not just a
throwaway test-environment replacement.

## Essential requirements
- Enterprise level application
  - modular (configuration level and container level modularity),
  - horizontally scalable,
  - observable (structured logging, health checks, metrics)
- Good coverage with unit tests
- Enterprise certificate authority functions with certificate profiles of modular features
- OCSP module enabled by default, and OCSP info is included in the issued certificates by default (if OCSP feature is for the certificate profile)
- TSA module enabled by default
- All admin functionality are designed to be accessed via REST API, API is versioned and API documentation is available for the running instance if not disabled.
  - API access is authorized with client certificate
  - API access with role check
- Native Go language implementation

## Functional goals

- Issue a root CA, intermediate CA and a REST-access leaf certificate on first run (or accept externally
  generated ones).
- API TLS access client certificates can be managed (first certificate is added with full access by default)
  - Roles are defined code-level for the access different part of the functionalities. Roles can be managed for the API access.
  - Roles are: Admin (can alter application configuration), Manager (can list, issue, revoke certificates)
- Can define certificate profiles in dynamic configuration with modular features like OCSP (e.g. document-signing certificate) profiles are versioned
- Issue (leaf) certificates against defined certificate profiles. Can list an revoke certificates.
- Publish CRLs and answer OCSP requests for every non-root certificate.
- Run an RFC 3161 Time-Stamp Authority.
- Serve AIA (`caIssuers`), CRL, OCSP, and TSA endpoints over HTTPS with no
  redirects.
- Everything reachable and scriptable over one REST API. No feature that
  requires a browser.
- Deploy as a single static binary / single container image, depending on
  nothing beyond the language runtime and OS libraries at container-build
  time (minimal bundled third-party services). (Database and persistency layer)
- **Modular by construction**: CA core, revocation (CRL/OCSP), and TSA are
  independently enable/disable-able via config, so a deployment that only
  needs, say, CA + OCSP doesn't run or expose the TSA surface at all.
  Later iterations may enable container-level modularity by adding functions with composition.
  Modules are not dynamic and cannot be added/switched on-off runtime.
- **Production-ready cross-cutting concerns, designed in from v1** (not
  necessarily all fully built in v1, but the architecture must not
  preclude them):
  - Structured logging behind a small interface, emitting to whatever the
    deployment's log pipeline expects (JSON to stdout is the default —
    the norm for container log collection into ELK/Loki/CloudWatch/etc.).
  - Liveness/readiness health-check endpoints suitable for container
    orchestrators (Container healthcheck, Kubernetes probes).
  - Metrics endpoint (Prometheus exposition format) for issuance rates,
    OCSP/TSA request latency and error rates, datastore health.
  - A storage interface that isn't hard-wired to SQLite, so a
    horizontally-scaled deployment can point multiple stateless API
    instances at a shared Postgres without an API rewrite.
  - Container ready configuration: environment variables override configuration file
  - Graceful shutdown, request timeouts, and rate limiting on the public
    unauthenticated endpoints (`/v1/ocsp`, `/v1/tsa`).

## Non-goals (at least for v1)

- Not a general-purpose, standards-maximal CA product (no ACME, no CMP, no
  SCEP, no multi-tenant org hierarchy) — these are explicit stretch/later
  items, not v1 scope.
- No built-in HSM integration in v1 (see Security below for the seam left
  for it).
- Not shipping a clustered/HA deployment topology in the very first cut —
  but unlike the original test-env-replacement scope, the architecture
  (stateless API layer, pluggable datastore, no in-process-only state)
  must not preclude running it that way later. "No HA in v1" is a
  sequencing choice, not a design ceiling.

## Other requirements

| Requirement | v1 approach |
|---|---|
| AIA `caIssuers` on every non-root cert | issuer cert URL templated into every issued cert at signing time, controlled by certificate profile |
| CRL DP on every non-anchor cert | same |
| AIA OCSP on every non-anchor cert | same |
| HTTPS only, no redirects | REST server terminates TLS itself (or expects to sit behind a dumb TLS-terminating proxy — see Architecture) |
| TSA validity ~2 years | profile-configurable |

## Building blocks

TODO: add admin access and dynamic configuratio to the graph below
```
                         ┌───────────────────────────┐
   clients  ───────────► │        REST API            │  HTTPS
   (zdoc-cli, curl, ...) │  /v1/*  /healthz  /metrics  │
                         └─────────────┬───────────────┘
                                       │
                 ┌─────────────────────┼─────────────────────┐
                 ▼                     ▼                     ▼
         ┌───────────────┐   ┌────────────────┐   ┌────────────────┐
         │  CA engine     │   │  Revocation     │   │  TSA engine     │
         │  issue/revoke  │   │  CRL + OCSP     │   │  RFC 3161       │
         │  (always on)   │   │  (togglable)    │   │  (togglable)    │
         └───────┬───────┘   └────────┬────────┘   └────────┬────────┘
                 │                    │                     │
                 └────────────┬───────┴─────────────────────┘
                               ▼
                      ┌─────────────────┐
                      │  Key store       │  abstraction: file-backed PKCS#8
                      │  (pluggable)     │  now, PKCS#11/KMS seam for later
                      └────────┬────────┘
                               ▼
                      ┌─────────────────┐
                      │  Datastore       │  interface first, SQLite (v1
                      │  (pluggable)     │  default) or Postgres — certs,
                      │                  │  serials, revocations, profiles,
                      │                  │  audit log
                      └─────────────────┘

   Cross-cutting, wired through every module above:
   structured logging · health checks · metrics · graceful shutdown
```

Modules (each independently testable, communicating only in-process in v1 —
no internal network hops to keep "modular" from becoming "microservices
sprawl"):

1. **`pki` core** — certificate issuance logic: takes a profile + subject +
   public key (or generates the keypair server-side for the P12-equivalent
   flow) and produces a signed certificate. Wraps the crypto library.
   Always on — the service has no purpose without it.
2. **`revocation`** — CRL generation (scheduled + on-demand) and an OCSP
   responder (RFC 6960) signed either by the issuing CA key directly or a
   delegated OCSP-signing key. Enable/disable via config; when disabled, no
   `/v1/crl/*` or `/v1/ocsp` routes are registered.
3. **`tsa`** — RFC 3161 request parsing and token generation, its own
   signing identity issued by the CA engine at bootstrap. Enable/disable
   via config; when disabled, `/v1/tsa` is not registered.
4. **`profiles`** — certificate profile definitions as versioned
   config/code (key usage, EKU, validity, AIA/CDP/OCSP URL templates, SAN
   rules), not database rows edited through a UI. A profile is just data;
   changing one is a config change + restart, reviewable in a PR.
5. **`keystore`** — abstraction over "where do private keys live." v1:
   encrypted file per key (`file`, the default). Phase 5 adds two more
   backends behind the same seam, selected via `keystore.driver`: `vault`
   (HashiCorp Vault's Transit secrets engine — keys never leave Vault,
   `Sign` is a network round trip) and `pkcs11` (a real HSM or SoftHSM2,
   built only into the opt-in cgo binary — see `Dockerfile.pkcs11` —
   since it needs to `dlopen` a vendor `.so` the default
   `CGO_ENABLED=0` scratch build can't load). None of `pki`/`tsa`/
   `revocation` changed to support this — they only ever held a
   `keystore.KeyStore` interface value.
6. **`store`** — issued-certificate ledger, serial number allocation,
   revocation records, audit log, ACME accounts/orders/EAB tokens/nonces,
   behind an interface. SQLite is the default (single file, trivially
   backed up, trivially mounted into a container volume); Postgres
   (`store.driver: postgres`) is the scale-out option, needed for
   HA/clustering (multiple stateless API replicas behind a load
   balancer) since SQLite is deliberately single-process (see
   `internal/store/sqlite.Open`'s `SetMaxOpenConns(1)`). Both
   implementations are hand-written SQL over `database/sql`, not an ORM —
   consistent with the rest of the codebase's near-zero-dependency style
   and so the two backends can't drift into different data-access
   paradigms.
7. **`api`** — the REST surface. Thin: validates input, calls into the
   modules above, serializes responses. No business logic lives here. Also
   owns the cross-cutting HTTP concerns: `/healthz`, `/readyz`, `/metrics`,
   structured request logging, rate limiting on public endpoints.
8. **`admin`** — a small CLI (not a web GUI) for the operations that are
   inherently operator-only: dynamic configuration like profile manipulation.
   API design standards are used.
8. **`management`** — a small CLI for the operations that are
   inherently operator-only: certificate operations, key rotation.
9. **`observability`** — cross-cutting, not a request-path module: a small
   logging interface (structured, JSON-to-stdout by default) that
   downstream deployments can wire into their log pipeline of choice, plus
   the Prometheus metrics registry used by `api` and the other modules.
10. **`acme`** — Phase 5's automated enrollment endpoint (RFC 8555 subset).
    TrustMate's certificates are role-bound API-access client certs, not
    domain-validated web certs, so authorization uses RFC 8555 section
    7.3.4's External Account Binding (an admin-issued, one-time HMAC
    credential — `POST /v1/acme/eab-tokens`, admin role required) instead
    of http-01/dns-01 domain challenges: an order goes straight from
    created to `ready` since EAB already proved an admin authorized this
    enrollment, the same trust decision `POST /v1/clients` makes
    directly. `internal/acme` holds the JWS/JWK primitives (used to parse
    and verify ACME's signed requests and compute the RFC 7638 account
    thumbprint); `internal/api/acme.go` wires them into the REST surface
    and reuses the same issuance path (`issueLeafCertificate`) as
    `POST /v1/clients`. Enable/disable via config (`modules.acme`, off by
    default); when disabled, no `/v1/acme/*` routes are registered.

## REST API sketch

```
GET    /v1/ca/root.pem               AIA caIssuers target
GET    /v1/ca/intermediate.pem       AIA caIssuers target

POST   /v1/certificates              issue a cert (CSR in, cert out)
GET    /v1/certificates/{serial}
POST   /v1/certificates/{serial}/revoke

GET    /v1/crl/{ca}.crl              CRL Distribution Point target        (revocation module)
POST   /v1/ocsp                      RFC 6960 OCSP responder              (revocation module)
POST   /v1/tsa                       RFC 3161 TSA (application/timestamp-query) (tsa module)

POST   /v1/acme/eab-tokens           admin issues an enrollment credential (acme module)
GET    /v1/acme/directory            RFC 8555 directory object            (acme module)
GET    /v1/acme/new-nonce            replay-nonce issuance                (acme module)
POST   /v1/acme/new-account          account creation, EAB required       (acme module)
POST   /v1/acme/new-order            order creation                       (acme module)
GET    /v1/acme/order/{id}
POST   /v1/acme/order/{id}/finalize  submit CSR, issue the certificate
GET    /v1/acme/authorization/{id}
GET    /v1/acme/certificate/{id}     PEM chain download

GET    /v1/profiles                  list, manage available certificate profiles
POST   /v1/profiles/reload           re-read profile config without restart

GET    /v1/audit                     issuance/revocation audit trail

GET    /healthz                      liveness probe
GET    /readyz                       readiness probe (datastore reachable, etc.)
GET    /metrics                      Prometheus exposition format
```

Auth: mutual TLS client certs or a bearer token for `/v1/certificates` and
`/v1/profiles`; `/v1/crl`, `/v1/ocsp`, `/v1/tsa`, `/v1/ca/*.pem` stay
unauthenticated (they're public PKI endpoints by design, same as today's
Caddy-fronted setup). `/healthz`, `/readyz`, `/metrics` are typically only
exposed on a private/ops network, not through the public-facing proxy.
`/v1/acme/eab-tokens` requires admin role like `/v1/clients`; every other
`/v1/acme/*` route authenticates via its own RFC 8555 JWS signature
(account-key or, for `new-account`, the External Account Binding), not
mTLS or a bearer token — that's the entire point of ACME as an enrollment
mechanism, so requiring an existing client cert to obtain one would be
circular.

## Phased roadmap

**Phase 0**:
root+intermediate CA, admin REST TLS access certificate generation, file-based
key storage, SQLite schema, module enable/disable config
scaffolding, `/healthz`/`/readyz`, configuration, structured logging wired through from
the start and other enterprise level architecture elements.
Data structure with profiles, default profile is created for the initial intermediate and admin access certificate.

**Phase 1**: 
certificate issuance from a CSR against an example "document-signing" profile (`GET /v1/ca/*.pem`, `POST
/v1/certificates`), CRL generation + serving, OCSP responder.

**Phase 2**: RFC 3161 TSA endpoint with its own
server-issued signing identity — replaces the SignServer half.

**Phase 3**: profile config (multiple profiles, not hardcoded), client access control with roles (available roles are hardcoded properties of the application)
revocation via REST, audit log endpoint, `admin` and `management` CLI, `/metrics`,
request-level auth (mTLS or bearer tokens).

**Phase 4**: storage interface's Postgres implementation (alongside
SQLite), so the API layer can run as multiple stateless replicas behind a
load balancer. Implemented as part of Phase 5 (below), as a prerequisite
for its HA/clustering item — `store.driver: postgres` is an
application-level option; SQLite stays the default.

**Phase 5 (stretch)**: PKCS#11/KMS-backed keystore option, ACME endpoint
for automated client enrollment, HA/clustering topology, minimal
read-only status UI (explicitly *not* an admin/config UI — just "what's
issued, what's revoked").

Implemented: the KMS keystore option (HashiCorp Vault Transit —
self-hostable and cloud-neutral, matching this project's positioning —
`keystore.driver: vault`), PKCS#11 (`keystore.driver: pkcs11`, only in
the binary built with `-tags pkcs11`, see `Dockerfile.pkcs11`), the ACME
endpoint (module 10 above), and the HA/clustering prerequisites (Phase 4
Postgres, plus the bootstrap-race fix and other notes under "HA /
clustering considerations" below). Not implemented: the read-only status
UI — no existing scaffolding to build on (this is a REST-only, no-GUI
service by design), left for a later pass.

## Security considerations

- Private keys (CA and TSA signing keys) encrypted at rest even in the v1
  file-backed keystore; passphrase/KEK supplied at startup via env var or
  mounted secret, never stored alongside the encrypted key.
- All state-changing REST calls audit-logged (who, what profile, what
  serial, when) — append-only table, exposed read-only via `/v1/audit`.
- TSA responses must include a nonce echo and enforce monotonic-ish
  timestamps to make replay/backdating detectable, per RFC 3161 good
  practice. This guard (`internal/tsa`) is in-memory, per process, by
  design: under HA/clustering (multiple stateless replicas behind a load
  balancer), monotonicity holds per-replica, not service-wide — a
  deliberate tradeoff, not an oversight. RFC 3161's "monotonic-ish"
  property exists to catch gross backdating/replay of a *given* token,
  not to give strict cross-request ordering, and `/v1/tsa` is the
  endpoint every client hits most often (see the rate-limiting bullet
  below) — moving the guard into the shared store to close this narrow
  edge case would add a synchronous datastore round trip to the hottest
  request path for a marginal correctness gain.
- Rate-limit `/v1/ocsp` and `/v1/tsa` (public, unauthenticated) since
  they're the endpoints every client hits repeatedly.
- ACME's replay-nonce mechanism (RFC 8555 section 6.5), by contrast, *is*
  backed by the shared store (`store.ACMENonceRepository`), not held
  in-process — nonce issuance and consumption need to be correct across
  replicas (a client's `new-nonce` call and its follow-up request can
  land on different replicas), and ACME account/order setup is
  comparatively low-frequency and not latency-sensitive, unlike
  `/v1/tsa`, so the extra round trip is an acceptable cost there.

## HA / clustering considerations

Phase 5's HA/clustering item turned out to be mostly wiring and
verification against the existing design, plus two real gaps:

- **Shared datastore is required**: `store.driver: postgres` (see module
  6 above). SQLite remains intentionally single-process
  (`SetMaxOpenConns(1)` in `internal/store/sqlite/sqlite.go`) — that's
  not a bug to fix, it's the tradeoff for SQLite's zero-ops simplicity.
- **Bootstrap race, fixed**: `bootstrap.Run`'s first-run CA generation
  checks for existing CA material and generates it if absent — a
  classic check-then-act race if two replicas start simultaneously
  against a fresh, empty Postgres. `cmd/trustmated` now wraps that call
  in a Postgres advisory lock (`postgres.WithAdvisoryLock`,
  `postgres.BootstrapLockKey`) when `store.driver` is `postgres`, so
  only one replica performs first-run generation; the rest block
  briefly, then find CA material already present. SQLite deployments
  don't need this (single process by construction).
- **Keystore reachability**: every replica needs identical key access.
  The `vault` keystore backend satisfies this by being network-based.
  The `file` backend is not the HA-oriented option — using it under HA
  would need a shared read path and single-writer discipline for
  key generation/rotation; this is a documented constraint, not
  something the code coordinates for, since `vault`/`pkcs11` (a shared
  HSM) are the backends actually meant for multi-replica deployment.
- **CRL/OCSP need no changes**: `revocation.CRLBuilder`'s in-memory,
  per-process cache regenerates independently on each replica from the
  shared store when it goes stale — no cross-replica coordination
  needed, since it's purely a read-through cache over shared state.
- **TSA monotonicity**: per-replica, as discussed above.
- **Stateless auth, verified**: `requireRole` (`internal/api/auth.go`)
  re-checks the caller's role from the store on every request; there's
  no server-side session state anywhere in the request path, so nothing
  needed to change here.

## Open questions to resolve before starting

1. Auth for `/v1/certificates` / `/v1/profiles`: mTLS admin certs vs.
   bearer tokens — or is "only reachable on a private network" an
   acceptable v1 answer, deferring auth to phase 3? Given the broadened
   production-readiness goal, leaning towards not deferring this past
   phase 3.
2. Datastore interface shape: design it now against SQLite so a Postgres
   implementation is a drop-in later (decided direction — see Goals), but
   the exact interface (repository-per-module vs. one `store` interface)
   still needs a first pass once Phase 0 code exists.
3. What does "module enable/disable" actually gate at runtime — just
   route registration in `api`, or also background jobs (e.g. scheduled
   CRL regeneration) and bootstrap steps (e.g. TSA signing identity
   issuance at `/v1/init` time)? Needs a decision when Phase 0's config
   loader is written.

## Verifications of the implementation

- Revocation list info is already available in the intermediate certificate if module is enabled.
- `store.driver: postgres` behaves identically to the SQLite default for
  every existing route (issue/revoke/CRL/OCSP/TSA) — verified by running
  `internal/store/storetest`'s shared contract suite against both
  backends (`internal/store/sqlite` and `internal/store/postgres`).
- `keystore.driver: vault` produces certificates indistinguishable from
  `file`-backed ones (same seam, same `crypto.Signer` contract) —
  verified by `internal/keystore/keystoretest`'s shared contract suite,
  including a real signature-verification round trip, run against both.
- An ACME client can complete `new-account` (with External Account
  Binding) → `new-order` → `finalize` → certificate download without any
  domain-validation step, and the issued certificate carries the role
  bound to the EAB token that created the account — verified end to end
  in `internal/api/acme_test.go` against a from-scratch test ACME client
  (real ES256/HS256 JWS signing, not mocked).
- Two `trustmated` replicas started simultaneously against the same
  empty Postgres database produce exactly one root/intermediate CA, not
  two — verified by `TestWithAdvisoryLockSerializes` in
  `internal/store/postgres`, which checks the underlying mutual-exclusion
  property `cmd/trustmated`'s bootstrap wrapping depends on.
