# Tasks

Feature: agent-okta-d-auto-review | Created: 2026-10-03 | Source PRD: specs/archive/261003-agent-okta-d-auto-review/agent-okta-d-auto-review-PRD.md

Status: Complete (FR-R01 production adapters deferred, see docs/deferred.md)

## Progress Summary
10/10 tasks complete (FR-R01 real AWS/hardware adapters explicitly deferred, not counted as done)

## Tasks
- [x] P1.1 FR-R01 (in-scope part): WARN at startup and doctor warn for file signer. Deps: none. Acceptance: unit tests.
- [x] FR-R02 (P1): One provider's "definitive" Okta rejection revokes every provider and exits the daemon. Acceptance: see spec.md FR-R02.
- [x] FR-R03 (P2): `revoke` signals whatever PID the pidfile names. Acceptance: see spec.md FR-R03.
- [x] FR-R04 (P2): Socket creation permission window and directory not enforced. Acceptance: see spec.md FR-R04.
- [x] FR-R05 (P2): Linux peer credentials do not include supplementary groups, and this is undocumented for operators. Acceptance: see spec.md FR-R05.
- [x] FR-R06 (P2): Scrubber only learns static secrets; refresh tokens and opaque OAuth tokens rely on `SecretString` alone. Acceptance: see spec.md FR-R06.
- [x] FR-R07 (P2): IPC server has no idle/write timeout or connection cap. Acceptance: see spec.md FR-R07.
- [x] FR-R08 (P2): Provider HTTP clients follow redirects. Acceptance: see spec.md FR-R08.
- [x] FR-R09 (P2): Spec tracking files and DEV-FLOW status are stale. Acceptance: see spec.md FR-R09.
- [x] FR-R10 (P2): Test and CI coverage gaps for platform-tagged code; misleading config error field. Acceptance: see spec.md FR-R10.

Deferred: FR-R01 real AWS SDK KMS/SecretsManager/STS adapters (needs sandbox AWS; no live systems here).
