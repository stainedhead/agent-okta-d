# Architecture: agent-okta-d
Date: 2026-10-03 | Status: Draft

## Architecture Overview
Clean Architecture, dependencies point inward. Concrete adapters are wired only in `cmd/agent-okta-d`.

## Component Architecture
- `internal/domain`: types and interfaces (no I/O imports). [package list in tasks WS-0]
- `internal/cache`: state machine, single-flight, scheduler (depends on domain, Clock).
- `internal/okta`: assertion builder, token client (HTTP), skew check.
- `internal/provider/{aws,github,servicenow,msgraph,secret}`: implement `Provider`; reach other providers only through `Deps`.
- `internal/store/{awssm,keychain,encfile}`; `internal/signer/{file,kms,keychain,tpm}`; `internal/sink`; `internal/ipc`; `internal/obs`; `internal/enroll`; `internal/config`.
- `pkg/client`: standalone, stdlib-only, no `internal/` import; wire types duplicated deliberately and pinned by golden tests.

## Layer Responsibilities
domain: rules and contracts. usecase (cache, doctor, revoke orchestration): policy. adapters: protocols, OS, cloud SDKs (hidden behind small interfaces so tests use fakes). cmd: wiring, signals, exit codes.

## Data Flow
Scheduler -> cache entry -> provider.Mint(Deps) -> okta client (signer signs assertion) -> credential -> cache + sinks; ipc handler -> cache (sync refresh if < min_ttl) -> response.

## Sequence Diagrams
[TBD in implementation: mint/refresh, revoke, enroll flows.]

## Integration Points
All external systems behind interfaces with fakes: Okta token endpoint, STS, KMS, Secrets Manager, GitHub API, ServiceNow whoami, Graph, Atlassian secret.

## Architectural Decisions
ADRs in `docs/architectural-decision-record.md`; initial: ADR-A dependency direction, ADR-B fakes-only testing, ADR-C `pkg/client` independence, ADR-D build tags for platform code, ADR-E assumptions register.
