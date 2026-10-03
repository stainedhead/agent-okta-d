# Architectural decision record

Record significant architecture decisions here, one entry per decision (context, decision, consequences, status). The decisions already made as inputs to the PRD (D1 to D7: Okta OIDC as identity root, daemon rather than wrapper CLI, stock `aws`/`gh`/`git`, custom CLIs limited to `snow`/`outlook`/`teams`, Atlassian via Rovo MCP, delegated Microsoft 365 access, GitHub EMU user credentials) are listed in section 2 of `../agent-okta-d-PRD.md` and should be migrated into formal entries as implementation starts.


## ADR-A: Dependency direction (Accepted, 2026-10-03)
Context: the daemon talks to HTTP, KMS, Keychain, the filesystem and several vendor APIs. Decision: Clean Architecture; `internal/domain` imports only the standard library and defines every contract; adapters depend inward; concrete wiring happens only in `cmd/agent-okta-d`. Consequences: each workstream tests against fakes (`internal/domain/domaintest`); changes to domain contracts need one owner and an ADR.

## ADR-B: Fakes-only testing (Accepted, 2026-10-03)
Decision: no test or build step contacts a live system or needs a credential. Okta, STS, GitHub, ServiceNow, Graph, KMS and Secrets Manager are `httptest` servers or interface fakes. Consequences: real-system acceptance is deferred to the M0 checklist and sandbox runs; fakes are derived from documented protocol shapes and covered by golden tests.

## ADR-C: pkg/client independence (Accepted, 2026-10-03)
Decision: `pkg/client` is stdlib-only and never imports `internal/`. Its wire types are deliberately duplicated from `internal/domain/wire.go` and both are pinned to the golden JSON in `internal/domain/testdata/wire`. Consequences: no accidental coupling of consumers (agent-cli-core) to daemon internals; a wire change must touch both copies and the goldens, which is a semver decision.

## ADR-D: Build tags for platform code (Accepted, 2026-10-03)
Decision: peer credentials, Keychain and TPM code sit behind build tags (`linux`, `darwin`) with a portable fake or stub for every other platform, so all three targets (darwin/arm64, linux/amd64, linux/arm64) compile on every PR. Consequences: stubs return `ErrConfig` where the platform cannot support a feature.

## ADR-E: Assumptions register (Accepted, 2026-10-03)
Decision: each unconfirmed vendor behavior is an `ASSUMPTION(A-xx)` code marker plus a row in `docs/assumptions.md` and `docs/m0-spike-checklist.md`; a test fails if a marker is not registered (AC-016). Consequences: an assumption can never silently become a fact.

## ADR-F: Dependency choices (Accepted, 2026-10-03)
Decision: stdlib only for `internal/domain`, `pkg/client` and the WS-0 skeleton (go.mod has no requirements). JOSE, YAML and AWS SDK v2 are added only by the workstream whose adapter needs them (config, okta/signer, store/awssm, signer/kms), kept out of `domain` and `pkg/client`; each addition is recorded here when made. Consequences: `go mod tidy` stays a no-op until then.

## ADR-G: Error-code wire contract (Accepted, 2026-10-03)
Decision: the `error` field of the JSON error body is authoritative (`reauth_required` 401, `revoked` 403, `unauthorized` 403, `not_configured` 404, `degraded` 503 with Retry-After); HTTP status is the fallback. Consequences: the 403 shared by revoked and unauthorized stays distinguishable.
