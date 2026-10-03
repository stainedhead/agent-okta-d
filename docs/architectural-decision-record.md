# Architectural decision record

Record significant architecture decisions here, one entry per decision (context, decision, consequences, status). The decisions already made as inputs to the PRD (D1 to D7: Okta OIDC as identity root, daemon rather than wrapper CLI, stock `aws`/`gh`/`git`, custom CLIs limited to `snow`/`outlook`/`teams`, Atlassian via Rovo MCP, delegated Microsoft 365 access, GitHub EMU user credentials) are listed in section 2 of `../specs/261003-agent-okta-d/agent-okta-d-PRD.md`; they are inputs to the entries below and have not been migrated into formal entries individually.


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
Decision: stdlib only for `internal/domain` and `pkg/client`. Outcome as built: the only third-party requirement is `go.yaml.in/yaml/v3` (config, `internal/config` only); JOSE/JWS, the Okta client and the AES-based store are implemented with the standard library; the AWS SDK v2 was NOT added. Consequences: no production KMS, Secrets Manager or STS adapter exists (see ADR-H); `go mod tidy` is checked in CI.

## ADR-G: Error-code wire contract (Accepted, 2026-10-03)
Decision: the `error` field of the JSON error body is authoritative (`reauth_required` 401, `revoked` 403, `unauthorized` 403, `not_configured` 404, `degraded` 503 with Retry-After); HTTP status is the fallback. Consequences: the 403 shared by revoked and unauthorized stays distinguishable.

## ADR-H: AWS SDK adapters deferred behind interfaces (Accepted, 2026-10-03)
Context: ADR-B forbids network and credentials in builds and tests, and ADR-F keeps dependencies minimal. Decision: KMS signing, Secrets Manager and STS are consumed through interfaces (`kms.KMSAPI`, `awssm.SecretsManagerAPI`, `aws.STSClient`) injected via `app.Env`; `DefaultEnv` leaves them nil. A config that needs one fails closed with `ErrConfig` ("not available in this build", exit 78). Consequences: the shipped binary cannot use the `kms` signer, the `aws-secretsmanager` store, the `atlassian` provider or the AWS doctor probe until a follow-up adds the SDK. Status: open follow-up.

## ADR-I: No revoke endpoint; revoke by signal and pidfile (Accepted, 2026-10-03)
Decision: the wire API is read/refresh only. `revoke` signals the daemon (SIGUSR1) through a pidfile next to the socket and wipes the sinks itself, so it works when the daemon is down. The daemon runs the sequence (revoked state, sinks removed, provider revoke hooks, forget secrets, critical audit event) and exits 77. Hardening (review FR-R03): the pidfile is 0640 and `revoke` signals only after the socket peer pid matches the pidfile pid. Consequences: a caller in `ipc.allow_gids` cannot trigger revoke over the API; the operator needs OS-level access to the daemon process.

## ADR-J: Startup self-test policy (Accepted, 2026-10-03)
Decision: a provider failing with a config, policy or provider error is not registered (API answers 404); transient errors and `reauth_required` keep it; a definitive Okta rejection or clock skew of 30 s or more is fatal (exit 77 for the rejection); the daemon's primary gid in `ipc.allow_gids` is a hard failure, uid 0 only a warning. Probes run in `doctor` only.

## ADR-K: file-encrypted store key derivation (Accepted, 2026-10-03)
Decision: the file-encrypted store derives its data key from a deterministic RS256 signature over a fixed label, so the key never rests next to the data. ES256 signatures are randomized and are refused for this store. Consequences: the store is tied to the signer key; rotating the signer key requires re-enrolling stored user credentials.

## ADR-L: Provider-scoped config additions (Accepted, 2026-10-03)
Decision: beyond the PRD sample, config gained optional `okta.authorization_servers` (name to id and audience), `store.path`, `github.probe_repo`, `msgraph.probe_other_user` and `atlassian.interval_seconds`. Audience defaults: `aws` `sts.amazonaws.com`, `servicenow` the instance URL (unverified against a tenant). The default client socket path (`pkg/client`) differs from the default `ipc.socket` (per-agent directory); consumers must set `AGENT_OKTA_D_SOCKET` or `ipc.socket` accordingly.
