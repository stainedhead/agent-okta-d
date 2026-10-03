# Plan: agent-okta-d
Date: 2026-10-03 | Status: Planning

## Development Approach
TDD (failing test first), fakes only, Clean Architecture. Priority order per spec section 4. Each workstream (WS) owns disjoint package directories, so agents can work in parallel git worktrees and merge without conflicts. Shared contracts live in `internal/domain` and are frozen by WS-0 before fan-out; any later change to them is made by one owner via a small PR and an ADR.

## Phase Breakdown
| Phase | Content | Workstreams |
|---|---|---|
| 1 Skeleton + pkg/client | module layout, `internal/domain`, CI alignment, `pkg/client` + fake daemon, `docs/assumptions.md`, `docs/m0-spike-checklist.md`, first-tag readiness (DEP-1) | WS-0 (serial), then WS-A |
| 2 Core daemon | config, Okta assertion + file signer, cache/scheduler, ipc, sink, obs, then integration (app wiring, doctor, status, revoke, cmd) | WS-B, WS-C, WS-D, WS-E, WS-F parallel; WS-INT serial after |
| 3 AWS | provider/aws, `configure aws` | WS-G |
| 4 GitHub | stores, provider/github, enroll/github, credential helper, gh shim | WS-H (stores first), WS-H2 |
| 5 ServiceNow | provider/servicenow | WS-I |
| 6 msgraph | provider/msgraph, enroll/msgraph | WS-J |
| 7 Atlassian | provider/secret | WS-K |
| 8 Signers | signer/kms, keychain, tpm (file done in WS-C) | WS-L |
| 9 Docs/hardening | user-docs, ADRs, ci.yml, skill-update note, final quality pass | WS-INT |

## Parallelizable workstreams (disjoint directories)
| WS | Owns (only these dirs) | Depends on |
|---|---|---|
| WS-0 | `internal/domain/`, `go.mod`, `.github/`, `Makefile`, `docs/` stubs | none (serial, first) |
| WS-A | `pkg/client/` (incl. `pkg/client/clienttest/` fake daemon) | WS-0 for wire type names only |
| WS-B | `internal/config/` | WS-0 |
| WS-C | `internal/okta/`, `internal/signer/` (interface adapters, `file/`) | WS-0 |
| WS-D | `internal/cache/` | WS-0 |
| WS-E | `internal/ipc/` (peercred with build tags) | WS-0 |
| WS-F | `internal/sink/`, `internal/obs/` | WS-0 |
| WS-INT | `cmd/agent-okta-d/`, `internal/app/` (doctor, status, revoke, wiring) | WS-B..F |
| WS-G | `internal/provider/aws/` | WS-INT contract only |
| WS-S | `internal/store/{awssm,keychain,encfile}/` | WS-0 |
| WS-H | `internal/provider/github/`, `internal/enroll/github/`, `cmd` shim assets under `internal/provider/github/` | WS-0, WS-S interface only |
| WS-I | `internal/provider/servicenow/` | WS-0 |
| WS-J | `internal/provider/msgraph/`, `internal/enroll/msgraph/` | WS-0, WS-S interface only |
| WS-K | `internal/provider/secret/` | WS-0, WS-S interface only |
| WS-L | `internal/signer/kms/`, `internal/signer/keychain/`, `internal/signer/tpm/` | WS-0 |
Rule: a WS never edits another WS's directory; `cmd/` registration of new providers is a one-line change made by WS-INT at merge time (providers register via a constructor listed in `internal/app/registry.go`).
After WS-0 and WS-A, WS-B..F, WS-S and WS-G..L can all run concurrently against the domain interfaces, because each provider tests with fakes of `Deps`.

## Critical Path
WS-0 -> (WS-C, WS-D, WS-E, WS-F, WS-B) -> WS-INT -> end-to-end fake M1 test. WS-A is off the critical path but gates the first `pkg/client` tag (DEP-1) so it goes first.

## Testing Strategy
Unit with fake clock; `httptest` fakes for Okta, GitHub, ServiceNow, Graph, STS; in-process fake daemon for `pkg/client`; redaction fuzz; cross-compile all three targets; `go test -race`; coverage thresholds. No network, no credentials.

## Rollout Strategy
Out of scope for the build (REL-12). Releases are cut later by the pipeline; first tag `0.1.0` containing `pkg/client`.

## Success Metrics
All tasks accepted; gates green on all three targets; every assumption has a marker and a checklist row.
