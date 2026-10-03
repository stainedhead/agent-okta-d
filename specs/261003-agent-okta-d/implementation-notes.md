# Implementation Notes: agent-okta-d
Date: 2026-10-03
Purpose: record decisions, edge cases, deviations and lessons as work proceeds. Update after each task.
## Technical Decisions
- WS-0: wire types live in `internal/domain/wire.go` (daemon side) and are duplicated in `pkg/client` by WS-A (ADR-C); both pinned to `internal/domain/testdata/wire/*.json`. Error body `error` code is authoritative over HTTP status (ADR-G).
- WS-0: `Deps` is an interface (fakeable); `SecretStore.Put` is compare-and-set with an expected-version string; `Sink` takes a `SinkSpec` per call; `Credential.Validate()` also requires non-zero `IssuedAt` and a positive TTL (static secrets set `ExpiresAt` to their re-fetch horizon).
- WS-0: shared fakes live in `internal/domain/domaintest` (FakeClock, FakeSigner, FakeProvider, FakeOkta, FakeStore, FakeSink, RecordingAudit, FakePeerCred, FakeDeps).
- WS-0: version stamp variables are in `internal/version` (not owned by a later WS); `Makefile` stamps them via ldflags.
## Edge Cases & Solutions
## Deviations from Plan
- WS-0 added `internal/domain/domaintest`, `internal/version` and a stub `pkg/client/doc.go` (package doc and wire-name table only) beyond the listed directories; WS-A owns `pkg/client` from here and may rewrite `doc.go`.
- Assumption marker canonical form is `ASSUMPTION(A-01)` to match register ids; `ASSUMPTION(A01)` is also accepted by the test.
- `.github/workflows/ci.yml` already guarded Go steps with `hashFiles`; WS-0 only added the coverage gate step and updated the comment.
## Lessons Learned
