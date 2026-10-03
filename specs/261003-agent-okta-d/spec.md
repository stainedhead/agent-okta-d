# Spec: agent-okta-d (credential daemon)

Created: 2026-10-03 | Source PRD: `specs/261003-agent-okta-d/agent-okta-d-PRD.md` (v0.2 plus build-phase additions in 9.1, 9.2, 14.1)

Evidence legend is preserved from the PRD: items the PRD marks unconfirmed remain explicit **assumptions** (register: `docs/assumptions.md`, ids A-xx, see `research.md`). They are never treated as facts.

## 1. Executive Summary
`agent-okta-d` is a Go daemon that runs beside an agent host. It signs Okta `private_key_jwt` client assertions with a key the agent can never read, obtains short-lived tokens, and serves them in the forms stock tools expect (AWS web-identity file, git credential helper / `GH_TOKEN`, Bearer for `snow`, Graph token for `outlook`/`teams`, a secret for the Atlassian MCP client). `pkg/client` is the small public Go library through which `agent-cli-core` talks to the daemon over a unix socket.

## 2. Problem Statement
Autonomous agents (LLMs with a shell) must reach AWS, GitHub, ServiceNow, Microsoft 365 and Atlassian as their own attributable identity without ever holding a long-lived secret or signing key, and with a kill switch. Today no single component does this for all five systems.

## 3. Goals / Non-Goals
Goals: PRD G1-G6 (no agent-readable long-lived secret; per-agent identity; invisible refresh; one binary and one config; fail closed; auditable without logging secrets).
Non-goals: authorization decisions; human login; LLM provider credentials; native Windows; MCP gateway; M6 Okta-roadmap evaluation, Entra Agent User spike and P2 items (unless trivial) in this build; M0 live spikes (replaced by `docs/m0-spike-checklist.md`).

## 4. Build constraints (from requester)
- Go 1.27, Clean Architecture (domain/provider interfaces inward; concrete wiring in `cmd/`).
- Targets: darwin/arm64, linux/amd64, linux/arm64. Platform code behind build tags with stubs/fakes elsewhere.
- No live external system or credential ever: every external is an interface with a fake or an `httptest` server.
- Priority order: (1) skeleton + `pkg/client`; (2) core daemon; (3) AWS; (4) GitHub; (5) ServiceNow; (6) msgraph; (7) Atlassian/secret provider; (8) signers (file, KMS, Keychain, TPM).

## 5. Functional Requirements
IDs map to PRD requirement ids; the PRD text is authoritative. Priority group = build order above.

| Spec ID | PRD ids | Summary | Group |
|---|---|---|---|
| FR-001 | CLI-1..CLI-5 (CLI-6 P1) | `pkg/client`: constructor, Credential/Refresh/Status/Identity, typed errors, stdlib-only, fake-daemon tests, golden wire tests | 1 |
| FR-002 | FR-1, 11 | Single binary, subcommands (`run`, `token`, `status`, `doctor`, `version`, `credential-helper`, `env`, `enroll`, `configure`, `revoke`), exit codes 77/78 (FR-15) | 1-2 |
| FR-003 | 10, FR-1 | YAML config load, validation, defaults, `ErrConfig` | 2 |
| FR-004 | 6.3, FR-2 | Okta client assertion builder + token client (RS256; ES256 assumption A-xx), `jti`, 429 handling, clock-skew check | 2 |
| FR-005 | FR-3, FR-4, FR-5, FR-6, FR-17, error taxonomy | Cache entry state machine, single-flight, scheduler with fake clock, backoff, `degraded`, `revoked` (two confirmations within 30 s), `reauth_required` | 2 |
| FR-006 | FR-7, 11 | Unix-socket HTTP API, peercred (build-tagged; fake on other platforms), gid allow-list per provider | 2 |
| FR-007 | FR-8 | Atomic file sink (temp, fsync, rename), mode/owner, wipe at start and on stop/revoke | 2 |
| FR-008 | FR-10, FR-11 | JSON logging, redaction layer (`SecretString`), audit events | 2 |
| FR-009 | FR-9, FR-16, 13 | `doctor`, `status`, startup self-test, `revoke` sequence | 2 |
| FR-010 | AWS-1..5 | AWS provider: token file, 50 % refresh, `configure aws`, doctor via fake STS, delete on revoke | 3 |
| FR-011 | GH-1..9, FR-18, MG-3 | Secret-store abstraction (`awssm`, `keychain`, `encfile` over interfaces) and GitHub provider (pat, oauth_device), credential helper, `gh` shim, `enroll github`, expiry warnings | 4 |
| FR-012 | SN-1..4 | ServiceNow provider, `min_ttl_seconds` sync refresh, doctor; P2 SN-5 only if trivial | 5 |
| FR-013 | MG-1..6 | msgraph provider (refresh-token flow, rotation persisted before use, `reauth_required` mapping, doctor incl. negative test), `enroll msgraph` device code against a fake | 6 |
| FR-014 | AT-1..3 | Generic `secret` provider and 0440 file sink; AT-4 P1 | 7 |
| FR-015 | FR-2, 4 | `Signer` interface; `file` signer; KMS (with DER to JOSE conversion), Keychain, TPM behind narrow interfaces/build tags; refuse world-readable key file | 8 (file signer needed in group 2) |
| FR-016 | SKILL-*, REL-*, BLD-* | CI workflow alignment (BLD-1..6), version command (REL-4); skill update is a root-repo PR (documented, not done here) | 1 |
| FR-017 | 9.2, 14.1 | `docs/assumptions.md`, `docs/m0-spike-checklist.md`, ADR entries | 1 |

P1/P2 items (FR-12 metrics, FR-13 hot reload, FR-14 memory hygiene, GH-10/11/12, MG-7/8, AT-2c, AWS-6, SN-5) are implemented only if trivial; otherwise listed as deferred in `status.md`.

## 6. Non-Functional Requirements
Security (unix socket only, 0640 config, refuse world-readable key, fail closed, no secrets in logs/panics); Availability (survive 30 min Okta outage, serve cached); Performance (cached `token` < 10 ms, cold refresh < 2 s p95 against fakes); Portability (three targets, build tags); Observability (audit fields per PRD 12); Quality gates (gofmt, vet, golangci-lint, `go test -race`, coverage 80 % internal / 90 % `pkg/client`).

## 7. System Architecture
Layers: `domain` (Credential, SecretString, states, error taxonomy, Provider/Signer/Store interfaces) <- `usecase` (cache/scheduler, mint orchestration, revoke, doctor) <- `adapters` (okta http, ipc, sink, obs, signers, stores, providers) <- `cmd/agent-okta-d` (wiring). See `architecture.md`.

## 8. Scope of Changes
New: `cmd/agent-okta-d`, `internal/{domain,config,signer,okta,provider,store,enroll,cache,ipc,sink,obs}`, `pkg/client`, `docs/assumptions.md`, `docs/m0-spike-checklist.md`, `user-docs/*`. Modified: `.github/workflows/ci.yml` (BLD-1..6), `Makefile`, `docs/architectural-decision-record.md`. Dependencies: stdlib first; JOSE/YAML and AWS SDK v2 only where an adapter needs them, kept out of `domain` and `pkg/client`.

## 9. Breaking Changes
None (no prior release). `pkg/client` starts at 0.y.z; surface changes are semver decisions (CLI-6).

## 10. Success and Acceptance Criteria
- Every task in `tasks.md` passes its acceptance criteria and the quality gates.
- Each PRD milestone M1-M5 behavior is demonstrated against fakes (not real systems): e.g. M1 token file rotates over a simulated 24 h with fake clock; M2 expired PAT yields `reauth_required` and no retry loop; M3 disabled-user fake yields rejection; M4b rotated refresh token persisted before use; cross-mailbox fake returns 403.
- Real-system acceptance remains with the later human M0/sandbox work (recorded in the spike checklist).
- No test needs network or credentials; no secret appears in logs (fuzz test).

## 10a. Numbered acceptance criteria (map to FRs)
- AC-001 (FR-001): `pkg/client` against the fake daemon returns credentials; each HTTP error shape maps to the documented typed error; `go list -deps` shows stdlib only.
- AC-002 (FR-002/009): `run` exits 78 on invalid config and 77 after `revoked`; `version` prints semver/commit/date.
- AC-003 (FR-003): invalid or missing config fields produce `ErrConfig` naming the field, never echoing secret values.
- AC-004 (FR-004): assertion has correct iss/sub/aud/exp(60 s)/unique jti/kid; 429 honors reset header; `invalid_client` is `ErrAuthDefinitive`, 5xx is `ErrTransient`.
- AC-005 (FR-005): fake-clock test: refresh at 50 % +/- jitter; backoff 1-60 s; `degraded` at expiry-30 s; `revoked` only after two definitive errors within 30 s; `reauth_required` never retried.
- AC-006 (FR-006): caller outside allow-listed gid is refused; revoked state returns 403; degraded returns 503 with Retry-After.
- AC-007 (FR-007): kill between temp write and rename leaves no partial target; stale sinks wiped at start; removed on revoke.
- AC-008 (FR-008): fuzz finds no secret in any log/audit line, error path or recovered panic.
- AC-009 (FR-009): `revoke` runs the 6-step sequence in order (verified by recording fakes); doctor refuses a provider whose probe fails.
- AC-010 (FR-010): 24 h fake-clock run keeps token file valid, mode 0440, never partially written.
- AC-011 (FR-011): expired PAT -> `reauth_required` + alert, zero retries; credential helper `store`/`erase` leave the secret untouched; wrong login in doctor fails.
- AC-012 (FR-012): token with < min_ttl remaining triggers synchronous refresh; deactivated-user fake yields rejection on next call.
- AC-013 (FR-013): rotated refresh token persisted before the access token is returned (store failure -> no token served); `invalid_grant` -> `reauth_required`; cross-mailbox probe expects 403.
- AC-014 (FR-014): secret re-fetched on interval; file 0440 atomic; value never logged.
- AC-015 (FR-015): DER->JOSE vectors pass; world-readable key file refused; keychain/tpm packages compile on all three targets.
- AC-016 (FR-016/017): CI cross-compiles all targets without network credentials; every `ASSUMPTION(Axx)` marker appears in `docs/assumptions.md`.

## 10b. Edge cases and error paths
- External failures: every adapter maps network error, timeout, 429 (with Retry-After), 5xx to `ErrTransient`; only Okta definitive auth errors can cause `revoked`; provider-side 401 on user-credential providers means `reauth_required`.
- Empty/null: empty secret, empty token, missing `expires_at`, zero TTL, malformed JWT/JSON are `ErrProvider` and never cached or served.
- Concurrency: simultaneous `token` callers share one refresh (single-flight); concurrent refresh plus revoke resolves to revoked winning; secret-store writes are versioned (compare-and-set) so two writers cannot lose a rotated refresh token.
- Permission boundaries: peer-cred failure or unknown gid is deny; sinks and key files with wider modes than configured are refused; daemon running as the agent user fails `doctor`.
- Clock: skew >= 30 s fails self-test; wake-from-sleep triggers immediate refresh; monotonic time used for scheduling.
- Shutdown/crash: SIGKILL leaves sinks, wiped at next start; SIGTERM removes sinks.

## 10c. Open questions (owner / resolution path)
Build-phase decisions already made: assumptions are coded behind interfaces (owner: build agents). Remaining, carried from the PRD sections 16 and 17.7 and owned by humans, resolved by the later M0 spike: A-01..A-12 in `research.md`, Hermes MCP header behavior (A-09), Apple signing (A-12), WSL2 service (A-11), shared pipeline/registry choices. Build-time open item: module dependency choices for JOSE/YAML/AWS SDK (owner: WS-0, record in ADR; default stdlib-only where practical).

## 11. Risks and Mitigation
| Risk | Mitigation |
|---|---|
| Unconfirmed vendor behavior (ES256, SCIM timing, CA behavior, etc.) | Assumption register, `ASSUMPTION(Axx)` code markers, spike checklist, interface seams |
| Fakes diverge from real systems | Fakes derived from documented protocol shapes; golden tests; contract tests reusable in the sandbox later |
| Parallel workstreams conflict | Disjoint package dirs; domain interfaces frozen in WS-0 before fan-out |
| Platform code untestable on CI | Build tags + stubs; cross-compile all targets per PR (BLD-3) |

## 12. Timeline and Milestones
Phased by build priority (see `plan.md`): P1 skeleton/client, P2 core, P3 AWS, P4 GitHub, P5 ServiceNow, P6 msgraph, P7 Atlassian, P8 signers, P9 docs/hardening. Calendar dates [TBD].

## 13. References
`specs/261003-agent-okta-d/agent-okta-d-PRD.md`; `/AGENTS.md`, `/INTENT.md`; root repo README/AGENTS/INTENT.
