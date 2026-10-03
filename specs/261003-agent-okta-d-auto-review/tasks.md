# Tasks

Feature: agent-okta-d-auto-review | Created: 2026-10-03 | Source PRD: specs/261003-agent-okta-d-auto-review/agent-okta-d-auto-review-PRD.md

Status: Planning

## Progress Summary
0/10 tasks complete

## Tasks
- [ ] P1.1 FR-R01 (in-scope part): WARN at startup and doctor warn for file signer. Deps: none. Acceptance: unit tests.
- [ ] FR-R02 (P1): One provider's "definitive" Okta rejection revokes every provider and exits the daemon. Acceptance: see spec.md FR-R02.
- [ ] FR-R03 (P2): `revoke` signals whatever PID the pidfile names. Acceptance: see spec.md FR-R03.
- [ ] FR-R04 (P2): Socket creation permission window and directory not enforced. Acceptance: see spec.md FR-R04.
- [ ] FR-R05 (P2): Linux peer credentials do not include supplementary groups, and this is undocumented for operators. Acceptance: see spec.md FR-R05.
- [ ] FR-R06 (P2): Scrubber only learns static secrets; refresh tokens and opaque OAuth tokens rely on `SecretString` alone. Acceptance: see spec.md FR-R06.
- [ ] FR-R07 (P2): IPC server has no idle/write timeout or connection cap. Acceptance: see spec.md FR-R07.
- [ ] FR-R08 (P2): Provider HTTP clients follow redirects. Acceptance: see spec.md FR-R08.
- [ ] FR-R09 (P2): Spec tracking files and DEV-FLOW status are stale. Acceptance: see spec.md FR-R09.
- [ ] FR-R10 (P2): Test and CI coverage gaps for platform-tagged code; misleading config error field. Acceptance: see spec.md FR-R10.

Deferred: FR-R01 real AWS SDK KMS/SecretsManager/STS adapters (needs sandbox AWS; no live systems here).
