# Tasks: agent-okta-d
Date: 2026-10-03 | Status: Planning

## Progress Summary
0/29 tasks complete

Format: `ID | WS | depends | est | acceptance`. All tasks: failing test first; gates (gofmt, vet, lint, `go test -race`) green.

## Phase 1 Skeleton + pkg/client (priority 1)
- P1.1 | WS-0 | none | 2h | `internal/domain`: Credential, SecretString (redacts in fmt, %#v, JSON, slog), states, error taxonomy, Provider/Signer/SecretStore/Clock/Deps interfaces; tests prove redaction.
- P1.2 | WS-0 | none | 1h | go.mod deps pinned, Makefile (`fmt lint test cross`), `ci.yml` per BLD-1..6 incl. cross-compile of 3 targets; `version` stamp variables.
- P1.3 | WS-0 | none | 1h | `docs/assumptions.md` (A-01..A-12) and `docs/m0-spike-checklist.md`; ADR-A..E in the ADR file.
- P1.4 | WS-A | P1.1 | 4h | `pkg/client` per CLI-1..CLI-4: constructor, calls, typed errors; godoc on all exports.
- P1.5 | WS-A | P1.4 | 3h | `clienttest` fake daemon over unix socket; golden wire tests; example test; stdlib-only import check test (CLI-5).
- P1.6 | WS-A | P1.4 | 1h | (P1) exported-API snapshot test (CLI-6).

## Phase 2 Core daemon (priority 2)
- P2.1 | WS-B | P1.1 | 3h | YAML config load/validate/defaults; invalid -> `ErrConfig` (exit 78); sample config with placeholders.
- P2.2 | WS-C | P1.1 | 4h | Assertion builder (claims, exp 60 s, unique `jti`, kid), token client with 429 `X-Rate-Limit-Reset`, 5xx/definitive error classification, skew check from `Date`; tests vs httptest Okta incl. invalid_client.
- P2.3 | WS-C | P2.2 | 2h | `file` signer (RS256, ES256 flagged A-01), refuses world-readable key file; `Public()` JWK.
- P2.4 | WS-D | P1.1 | 5h | Cache state machine, single-flight, scheduler (fraction, jitter, min margin), backoff 1-60 s, degraded, revoked on 2 definitive errors within 30 s, reauth_required; fake clock; 24 h simulation.
- P2.5 | WS-E | P1.1 | 4h | Unix-socket HTTP API per section 11, peercred (linux/darwin build tags + fake), gid allow-list, 503 + Retry-After, 403 when revoked.
- P2.6 | WS-F | P1.1 | 3h | Atomic sink (temp, fsync, rename, mode, wipe stale at start, remove on stop).
- P2.7 | WS-F | P1.1 | 3h | slog JSON handler with redaction, audit event emitter with PRD fields, redaction fuzz incl. error paths and panics.
- P2.8 | WS-INT | P2.1-P2.7 | 5h | `internal/app` wiring: provider registry, startup self-test, `doctor`, `status`, `revoke` sequence (6 steps), signals, exit codes 77/78; `cmd` subcommands `run token status doctor version revoke env`.
- P2.9 | WS-INT | P2.8, P1.5 | 2h | End-to-end test: daemon with fake Okta + `pkg/client` fake-free path; `token` returns cached credential < 10 ms.

## Phase 3 AWS (priority 3)
- P3.1 | WS-G | P2.8 contract | 4h | AWS provider: mint `agents-aws`, token file 0440 atomic, refresh at <= 50 %, delete on revoke (AWS-1,2,5).
- P3.2 | WS-G | P3.1 | 2h | `configure aws` snippet, doctor via fake STS GetCallerIdentity (AWS-3,4). Simulated 24 h rotation test (M1).

## Phase 4 GitHub (priority 4)
- P4.1 | WS-S | P1.1 | 4h | `encfile` store, `awssm` store over a `SecretsManagerAPI` interface (versioned atomic Put), `keychain` store behind build tag with stub.
- P4.2 | WS-H | P1.1 | 5h | GitHub provider modes pat/oauth_device, static-secret credential, 401 refetch once then reauth_required, 403/429 Retry-After (GH-1,2,9).
- P4.3 | WS-H | P4.2 | 3h | credential helper (get returns login/token, store/erase no-op), `env`, `gh` shim script, `configure git` (GH-3,4,8).
- P4.4 | WS-H | P4.2 | 3h | `enroll github` pat (stdin) and oauth_device (RFC 8628 against fake), expiry record + warnings (GH-5,6); doctor `GET /user` login check (GH-7).

## Phase 5 ServiceNow (priority 5)
- P5.1 | WS-I | P1.1 | 3h | Provider SN-1..4 with `min_ttl_seconds` sync refresh, whoami probe against fake; disabled-user fake path.

## Phase 6 msgraph (priority 6)
- P6.1 | WS-J | P1.1, P4.1 iface | 5h | Provider MG-1,2,4,5: refresh grant, persist rotated refresh token before returning access token, invalid_grant -> reauth_required, 5xx transient.
- P6.2 | WS-J | P6.1 | 3h | `enroll msgraph` device code vs fake; doctor incl. negative cross-mailbox 403 test (MG-6).

## Phase 7 Atlassian (priority 7)
- P7.1 | WS-K | P1.1, P4.1 iface | 3h | Generic `secret` provider, interval re-fetch, 0440 file sink (AT-1..3).

## Phase 8 Signers (priority 8)
- P8.1 | WS-L | P2.3 | 4h | KMS signer over `KMSAPI` interface; DER ECDSA to JOSE R||S conversion with vectors (FR-2, A-10).
- P8.2 | WS-L | P2.3 | 3h | Keychain signer (darwin build tag) and TPM signer (linux build tag) behind interfaces; stubs returning `ErrConfig` on other platforms; compile on all 3 targets.

## Phase 9 Docs and hardening
- P9.1 | WS-INT | all | 3h | `user-docs/` (install, config reference, troubleshooting); `doctor` enforces agent/daemon user separation check.
- P9.2 | WS-INT | all | 2h | Final gates on 3 targets, coverage thresholds, assumptions register cross-check (every `ASSUMPTION(` marker listed), deferred P1/P2 list in status.md, note for root-repo skill PR.

Total: 29 tasks.
