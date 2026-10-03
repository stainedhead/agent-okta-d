# Spec: agent-okta-d Review Fixes

Feature: agent-okta-d-auto-review | Created: 2026-10-03 | Source PRD: specs/archive/261003-agent-okta-d-auto-review/agent-okta-d-auto-review-PRD.md

## Executive Summary
Fix the findings from the automated code review of branch feat/agent-okta-d. No P0 blockers; 2 P1 and 8 P2 findings. FR-R01 (real AWS adapters) is deferred.

## Problem Statement
The agent-okta-d daemon has hardening gaps in revoke, socket setup, scrubbing, IPC limits, redirects, CI and docs, plus a dev-only signer warning gap.

## Goals / Non-Goals
Goals: implement FR-R02..FR-R10 and the in-scope part of FR-R01 (WARN and doctor warn on file signer). Non-goals: real AWS SDK adapters, live systems or credentials, new architecture, pkg/client API changes.

## User Requirements (Functional Requirements)
- FR-R01 (P1, deferred): No production-grade signer or AWS adapter exists in the shipped binary
- FR-R02 (P1): One provider's "definitive" Okta rejection revokes every provider and exits the daemon
- FR-R03 (P2): `revoke` signals whatever PID the pidfile names
- FR-R04 (P2): Socket creation permission window and directory not enforced
- FR-R05 (P2): Linux peer credentials do not include supplementary groups, and this is undocumented for operators
- FR-R06 (P2): Scrubber only learns static secrets; refresh tokens and opaque OAuth tokens rely on `SecretString` alone
- FR-R07 (P2): IPC server has no idle/write timeout or connection cap
- FR-R08 (P2): Provider HTTP clients follow redirects
- FR-R09 (P2): Spec tracking files and DEV-FLOW status are stale
- FR-R10 (P2): Test and CI coverage gaps for platform-tagged code; misleading config error field

### FR-R01 (P1, DEFERRED): No production-grade signer or AWS adapter exists in the shipped binary
Status: **Deferred with rationale; not implemented in this fix cycle.** Real AWS SDK KMS, SecretsManager and STS adapters cannot be verified without live AWS and no live systems or credentials are ever used in this workflow. Fakes-only tests would verify nothing about the real SDK behavior, and the AWS SDK dependency would need a separate CGO_ENABLED=0 three-target compile and size assessment. It is tracked as a follow-up requiring a sandbox AWS account.
Evidence: `internal/app/env.go` leaves `KMS`, `SecretsManager` and `STS` nil in `DefaultEnv`. `internal/signer/keychain/open_darwin.go`, `internal/signer/tpm/open_linux.go` and `internal/store/keychain/native_darwin.go` return `ErrConfig`. The `file` signer's own doc says "dev only". The only working signer keeps the private key on disk readable by the daemon uid, which weakens G1. The `atlassian` provider and the AWS `doctor` probe cannot run. `status.md` and user-docs state this accurately, and AC-015 only demands compile-ability, so this is a follow-up and not a spec violation.
Acceptance criteria (deferred follow-up, not part of this cycle):
- A KMS signer via the AWS SDK adapter behind `kms.KMSAPI`, selectable through `DefaultEnv`, with a contract test reusable against a sandbox.
- Production `SecretsManagerAPI` and `STSClient` adapters, verified against the real SDK in a manual spike.
Acceptance criteria (in scope now, fakes and local only, no new dependency):
- `agent-okta-d run` logs a WARN at startup when `signer.type: file` is used, and `doctor` marks it `warn`, asserted by unit tests.
- `status.md` and `docs/` list FR-R01 once as a deferred follow-up with this rationale.

### FR-R02 (P1): One provider's "definitive" Okta rejection revokes every provider and exits the daemon
Evidence: `internal/okta/client.go` `definitive` treats `access_denied` and `invalid_grant` as `ErrAuthDefinitive`. `internal/cache/cache.go` `handleFailure` counts confirmations per entry (`e.firstDef`) but `revokeLocked` in `internal/cache/sched.go` withdraws all entries, and `Run` exits 77 (supervisors then stop restarting). An authorization-server access policy or scope denial on a single provider (for example ServiceNow) that Okta reports as `access_denied` can therefore kill AWS and GitHub credentials as well. This is outside the "app disabled or key removed" intent. `access_denied` and `invalid_grant` for a client_credentials grant are also unconfirmed against a real Okta tenant.
Acceptance criteria:
- Only rejections that identify the client (`invalid_client`, `unauthorized_client`) trigger global revocation. Others (`access_denied`, `invalid_grant`) degrade or refuse the single provider, or are configurable.
- A test shows that two `access_denied` responses on one provider's auth server leave the other providers `valid`, and that two `invalid_client` responses still revoke all within the 30 s window.
- The behavior is recorded as a new assumption in `docs/assumptions.md` and the spike checklist.

### FR-R03 (P2): `revoke` signals whatever PID the pidfile names
Evidence: `internal/app/revoke.go` reads `agent-okta-d.pid` (written mode 0644, never removed after SIGKILL) and sends SIGUSR1 if `kill(pid, 0)` succeeds. After a crash and PID reuse, SIGUSR1 (default action: terminate) hits an unrelated process, possibly as root. The pidfile is also not checked for ownership or for being the daemon.
Acceptance criteria:
- `revoke` verifies the target is the daemon before signaling (for example, connect to the socket and compare the peer PID, or compare the process executable/start time), and refuses otherwise.
- The daemon writes the pidfile 0600/0640 (not world-writable directory dependent) and `WipeStale` or start removes a stale one.
- A test covers a pidfile naming a live unrelated process: no signal is sent, and the sinks are still wiped.

### FR-R04 (P2): Socket creation permission window and directory not enforced
Evidence: `internal/ipc/listen.go` binds under the process umask and then `chmod`s; `internal/app/daemon.go` `os.MkdirAll(dir, 0o750)` does not tighten an existing directory, and `os.Chown` of the socket to the allowed gid happens after bind and chmod. With a permissive umask there is a short window with a wider mode. In the multi-gid case the socket is 0666 and protection rests solely on peercred.
Acceptance criteria:
- The socket is bound with a restrictive umask (or inside a 0700 temp dir then renamed) so it is never wider than the target mode.
- `start` fails (ErrPolicy) if the socket directory exists and is world-accessible or not owned by the daemon user.
- A unit test asserts the mode after `ListenUnix` under `umask 000`.

### FR-R05 (P2): Linux peer credentials do not include supplementary groups, and this is undocumented for operators
Evidence: `internal/ipc/peercred_linux.go` returns only the primary gid (SO_PEERCRED); darwin returns the full xucred group list. An agent whose allowed group is supplementary works on macOS and is silently denied (403) on Linux. The behavior is only in a Go comment; `user-docs/getting-started.md` and `configuration.md` do not mention it.
Acceptance criteria:
- Either supplementary groups are resolved on Linux (via `/proc/<pid>/status` `Groups:` read through the verified pid, with a fail-closed fallback), or the limitation is stated in `user-docs/configuration.md` (`ipc.allow_gids`) and `troubleshooting.md`.
- A test (build-tagged linux) covers the chosen behavior.

### FR-R06 (P2): Scrubber only learns static secrets; refresh tokens and opaque OAuth tokens rely on `SecretString` alone
Evidence: `internal/app/deps.go` `guarded.Mint` registers only `KindStaticSecret` values with the Scrubber. msgraph refresh tokens (opaque, not JWT-shaped), refresh-token store reads, and GitHub OAuth device tokens are never registered, so if an error string or foreign library wraps one, only the `eyJ` pattern and key-name filter protect it. `Scrubber.Add` also grows without bound as `secret`/rotating values change (no eviction).
Acceptance criteria:
- Provider/store layers register rotated refresh tokens and OAuth access tokens with the scrubber when read or rotated.
- The scrubber de-duplicates and bounds its list (for example keeps only the N most recent values per source).
- A fuzz or table test in `internal/app` proves a rotated msgraph refresh token embedded in an error does not appear in log output.

### FR-R07 (P2): IPC server has no idle/write timeout or connection cap
Evidence: `internal/ipc/server.go` sets only `ReadHeaderTimeout: 5s`. There is no `IdleTimeout`, `WriteTimeout`, `MaxHeaderBytes`, or limit on concurrent connections. When the socket is 0666 (multi-gid), any local user can open many idle keep-alive connections before peercred denies them, exhausting file descriptors and starving the agent.
Acceptance criteria:
- `IdleTimeout`, `WriteTimeout` and a small `MaxHeaderBytes` are set, and a connection limit (for example `netutil.LimitListener` equivalent) is applied.
- A test opens more than the limit of idle connections and shows that an allowed caller can still be served after the idle timeout.

### FR-R08 (P2): Provider HTTP clients follow redirects
Evidence: only `internal/okta/client.go` sets `CheckRedirect` to `ErrUseLastResponse`. The shared `env.HTTP` client used by the github, servicenow and msgraph providers follows redirects, which can re-send POST bodies (refresh tokens, device codes) on 307/308 to an unexpected host.
Acceptance criteria:
- The default `Env.HTTP` (or each provider client) refuses cross-host redirects, or all redirects for token endpoints.
- A test per provider with an `httptest` redirect to a second server asserts the second server receives no request.

### FR-R09 (P2): Spec tracking files and DEV-FLOW status are stale
Evidence: `specs/archive/261003-agent-okta-d/status.md` and `tasks.md` still list P9.1 (user-docs) and P9.2 as open (28/30), although `user-docs/` has been delivered on this branch. `status.md` says Phase 9 is Open. P9.2 items (assumptions cross-check, coverage gate on three targets) are done in CI but not ticked.
Acceptance criteria:
- `tasks.md`, `status.md` and `DEV-FLOW-STATUS.md` agree with the delivered state, with the remaining deferrals listed once.
- The skill-PR note for the root repo is present as a tracked follow-up with an owner.

### FR-R10 (P2): Test and CI coverage gaps for platform-tagged code; misleading config error field
Evidence: `.github/workflows/ci.yml` runs `go test` only on ubuntu-latest, so `internal/ipc/peercred_darwin.go` and darwin-tagged stubs are only cross-compiled, never tested in CI. `cmd/agent-okta-d` has no tests. `NewSigner` passes `key_id` as the file `Path`, so file-signer errors name `okta.signer.path`, a key that does not exist in the config (`signer.key_id`). AC-007's kill-between-write-and-rename case is covered only by injected rename failures, not a real crash.
Acceptance criteria:
- A macOS job runs `go test ./internal/ipc/... ./internal/signer/... ./internal/store/...` (or the full suite).
- Config errors from the file signer name the real config key.
- A smoke test for `cmd/agent-okta-d` (`version` exit 0) exists.

## Non-Functional Requirements
Security: fail-closed, no secret leakage, negative tests. Reliability: go test -race ./... passes (-count=3 for cache, ipc, app). Performance: no hot-path regression. Observability: scrubbed structured logs for new paths. Portability: CGO_ENABLED=0 builds for darwin/arm64, linux/amd64, linux/arm64; coverage >= 90% per package; gofmt/vet/golangci-lint clean.

## System Architecture
Affected: internal/cache (FR-R02), internal/okta, internal/app (revoke, daemon, deps, env, doctor), internal/ipc (listen, server, peercred), internal/provider/*, internal/obs scrubber, cmd/agent-okta-d, .github/workflows/ci.yml, docs and user-docs. No new components.

## Scope of Changes
Modify the packages above plus tests; no new module dependencies (no AWS SDK).

## Breaking Changes
None to pkg/client. Config: possible new optional revocation-code setting (FR-R02); start may now fail on unsafe socket directory (FR-R04).

## Success and Acceptance Criteria
Each FR's acceptance criteria above are the gates, plus: all quality gates green, status.md and tasks.md accurate.

## Risks and Mitigation
Okta error semantics unverified against a real tenant (documented assumption). macOS CI job cannot be run locally (review workflow YAML carefully). Parallel edits in internal/app (use separate worktrees, merge in order).

## Timeline and Milestones
M1 P1 fixes (FR-R01 warning, FR-R02). M2 security cluster (R03, R06, R08). M3 ipc cluster (R04, R05, R07). M4 process (R09, R10). M5 final quality pass.

## References
specs/archive/261003-agent-okta-d-auto-review/agent-okta-d-auto-review-PRD.md; specs/archive/261003-agent-okta-d/
