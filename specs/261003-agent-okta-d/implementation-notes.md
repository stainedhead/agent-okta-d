# Implementation Notes: agent-okta-d
Date: 2026-10-03
Purpose: record decisions, edge cases, deviations and lessons as work proceeds. Update after each task.
## Technical Decisions
- WS-0: wire types live in `internal/domain/wire.go` (daemon side) and are duplicated in `pkg/client` by WS-A (ADR-C); both pinned to `internal/domain/testdata/wire/*.json`. Error body `error` code is authoritative over HTTP status (ADR-G).
- WS-0: `Deps` is an interface (fakeable); `SecretStore.Put` is compare-and-set with an expected-version string; `Sink` takes a `SinkSpec` per call; `Credential.Validate()` also requires non-zero `IssuedAt` and a positive TTL (static secrets set `ExpiresAt` to their re-fetch horizon).
- WS-0: shared fakes live in `internal/domain/domaintest` (FakeClock, FakeSigner, FakeProvider, FakeOkta, FakeStore, FakeSink, RecordingAudit, FakePeerCred, FakeDeps).
- WS-0: version stamp variables are in `internal/version` (not owned by a later WS); `Makefile` stamps them via ldflags.
- INT: `internal/app` owns all wiring; `cmd/agent-okta-d/main.go` only calls `app.Main` with `app.DefaultEnv()` and process signals. Every external seam is an `Env` field so the end-to-end test runs against fakes.
- INT: no revoke endpoint exists (wire API frozen). `revoke` reads `<socket dir>/agent-okta-d.pid`, sends SIGUSR1 and wipes the sinks locally; the daemon runs: (1) revoked state, API answers 403, (2) sinks removed, (3) provider Revoke hooks (steps 1-3 inside `cache.Revoke`), (4) forget in-memory secrets (scrubber reset; cache drops credentials), (5) critical audit event, (6) exit 77. Order proven in `TestRevokeSequence`.
- INT: startup self-test refuses (does not register) a provider with a config/policy/provider error; transient errors and `reauth_required` keep the provider; a definitive Okta rejection is fatal and exits 77; clock skew >= 30 s is fatal. Probes run only in `doctor`.
- INT: user separation: the daemon's primary gid in `ipc.allow_gids` is a hard failure (`ErrPolicy`, daemon refuses to start; doctor aborts); running as uid 0 only warns; supplementary membership is allowed (needed to chgrp sinks).
- INT: exit codes: 0 ok, 1 failure, 2 usage, 3 daemon unreachable (client commands), 77 revoked, 78 config.
- INT: the sink group is the first non-numeric `ipc.allow_gids` entry; the socket gets group = the single allowed gid (mode 0660) or mode 0666 with several (peer credentials still decide). `credential-helper` runs as the agent user: it needs a config readable by that user (no secrets in it) or `--login` and `--web-base`.
## Edge Cases & Solutions
## Deviations from Plan
- WS-0 added `internal/domain/domaintest`, `internal/version` and a stub `pkg/client/doc.go` (package doc and wire-name table only) beyond the listed directories; WS-A owns `pkg/client` from here and may rewrite `doc.go`.
- Assumption marker canonical form is `ASSUMPTION(A-01)` to match register ids; `ASSUMPTION(A01)` is also accepted by the test.
- `.github/workflows/ci.yml` already guarded Go steps with `hashFiles`; WS-0 only added the coverage gate step and updated the comment.
- INT config additions (WS-B fix, minimal): optional `okta.authorization_servers` (name -> id, audience; a name without an entry is its own id, audience defaults: aws `sts.amazonaws.com`, servicenow the instance URL, NEW ASSUMPTION), `store.path` (file-encrypted file, default `/var/lib/agentd/<id>/secrets.enc`, `/var/db/agentd/<id>` on macOS), `github.probe_repo`, `msgraph.probe_other_user`, `atlassian.interval_seconds` (default 900).
- INT: AWS SDK adapters are not in this build (see status.md Deferred). The file-encrypted store derives its key from a deterministic RS256 signature over a fixed label (ES256 refused).
- INT: tests for `internal/app` were written alongside the code rather than strictly before it (deviation from strict TDD for this integration task); coverage 93.4 %.
## Lessons Learned
