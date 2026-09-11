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
   encrypted file per key. Seam left open for PKCS#11 or a cloud KMS later
   without touching the CA/TSA/revocation logic.
6. **`store`** — issued-certificate ledger, serial number allocation,
   revocation records, audit log, behind an interface. SQLite is the v1
   default (single file, trivially backed up, trivially mounted into a
   container volume); Postgres is the scale-out option, chosen so
   supporting it later doesn't require touching call sites.
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
load balancer.

**Phase 5 (stretch)**: PKCS#11/KMS-backed keystore option, ACME endpoint
for automated client enrollment, HA/clustering topology, minimal
read-only status UI (explicitly *not* an admin/config UI — just "what's
issued, what's revoked").

## Security considerations

- Private keys (CA and TSA signing keys) encrypted at rest even in the v1
  file-backed keystore; passphrase/KEK supplied at startup via env var or
  mounted secret, never stored alongside the encrypted key.
- All state-changing REST calls audit-logged (who, what profile, what
  serial, when) — append-only table, exposed read-only via `/v1/audit`.
- TSA responses must include a nonce echo and enforce monotonic-ish
  timestamps to make replay/backdating detectable, per RFC 3161 good
  practice.
- Rate-limit `/v1/ocsp` and `/v1/tsa` (public, unauthenticated) since
  they're the endpoints every client hits repeatedly.

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
