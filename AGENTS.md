# AGENTS.md

Rules for AI agents and human contributors working in this repository.

## Project summary

`agent-okta-d` ("the daemon") is a credential daemon that runs beside each agent host (desktop or cloud). It authenticates to Okta with a private key the agent can never read, obtains short-lived OIDC tokens, and converts them into the credential forms that each downstream system's stock tooling already understands (AWS web-identity token file, git credential helper and `GH_TOKEN`, Bearer token for the `snow` CLI, a secret for the Atlassian MCP client, a delegated Graph token for the `outlook` and `teams` CLIs). The agent process never handles OIDC, never reads a long-lived secret and never sees a signing key.

Status: Draft PRD (`agent-okta-d-PRD.md`), no implementation yet. The PRD is the source of truth; its evidence legend (confirmed vs. unconfirmed items) must be preserved when summarising it.

`pkg/client` is consumed by [`agent-cli-core`](https://github.com/stainedhead/agent-cli-core), the shared CLI core library (its own repo); the `snow`, `outlook` and `teams` CLIs reach the daemon through the core.

## Doc routing

- Goal, direction or scope shift: update `INTENT.md` (why this tool exists and its wider context).
- Requirements: `agent-okta-d-PRD.md` (source of truth).
- Design decisions: `docs/architectural-decision-record.md`.

## Go layout (planned, per PRD section 9)

```
INTENT.md           why this exists and what it is for
cmd/agent-okta-d/   subcommands, signal handling, exit codes
internal/           config, signer, okta, provider, store, enroll, cache, ipc, sink, obs
pkg/client/         Go client library consumed by agent-cli-core (its auth package); the CLIs get it via the core
docs/               product and technical documentation
user-docs/          end-user documentation only (see rule below)
specs/              feature specs; completed specs go to specs/archive/
```

## Architecture and engineering standards

- Clean Architecture: domain and provider interfaces do not depend on infrastructure (HTTP, KMS, Keychain, filesystem). Dependencies point inward; wire concrete implementations in `cmd/`.
- Test-driven development: write the failing test first, then the code. Use fake clocks and mock Okta endpoints; no test may need real credentials or network access.
- Keep `internal/` packages small and cohesive; export only what other modules (`pkg/client`) need.
- Fail closed. Never log tokens, client assertions or key material; secret values use a redacting type.
- Record significant design decisions in `docs/architectural-decision-record.md`.

## Verification (run before every commit)

```
gofmt -l .
go vet ./...
golangci-lint run
go test ./...
```

`make fmt lint test` runs the same checks. All must pass cleanly.

## Security

- Never commit credentials: no private keys, tokens, PATs, client secrets, `.env` files or real tenant identifiers.
- Do not paste secrets into issues, PRs, logs or test fixtures.

## user-docs/ rule

`user-docs/` holds only files that help a user adopt, configure and use the tool: install, getting started, configuration reference, usage examples and troubleshooting. It is NOT for design, requirements, spec or process material, and it must not link into `specs/`. Put that material in `docs/` or `specs/` instead.
