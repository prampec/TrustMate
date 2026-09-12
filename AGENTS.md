# AGENTS.md

Instructions for AI coding agents working in this repository.

## Project

TrustMate is a self-contained Certificate Authority service (CA issuance,
CRL, OCSP, RFC 3161 TSA) written in Go. See `docs/design.md` for the full
design and `README.md` for the quick start.

## Status

Under development

## Build, test, lint

go is installed under ~/.local/go it should be on the path already. Check that before executing go and stop with failure if it is not the case.

```sh
go build ./...
go test ./...
go vet ./...
gofmt -l .        # should print nothing; run `gofmt -w .` to fix
```

Run the full suite above before considering a change complete.

Do not try docker or podman on this machine.

## Code style

- Standard Go formatting (`gofmt`); no custom style deviations.
- Keep packages under `internal/` independently testable; avoid new
  cross-package coupling not already implied by `docs/design.md`.
- No comments explaining *what* code does; only *why*, when non-obvious.

## PR / commit conventions

- Project is under git.
- Commit messages: short imperative summary line, no trailing period.
- Do add generated binaries, `.env`, or key material into VCS. Add any other new project files to VCS.
- You are free to commit, but must not push!

## Security notes

- This service handles private keys and issues certificates — never log
  private key material, and treat `internal/keystore` and `internal/pki`
  changes as security-sensitive (extra care, and mention in the PR body
  what was reviewed).
- Don't weaken TLS/crypto defaults (key sizes, signature algorithms) to
  make tests pass.
