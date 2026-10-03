# Data Dictionary: agent-okta-d
Date: 2026-10-03. Purpose: canonical definitions of types shared across packages. Frozen in workstream WS-0 before fan-out; changes need an ADR.

## Entities
- `Credential{Kind, Value SecretString, IssuedAt, ExpiresAt, Meta map[string]string}` (PRD 9). Kinds: `bearer`, `aws-web-identity`, `static-secret`.
- `CacheEntry{Key(provider,audience,scope), Credential, State, LastError, NextRefresh}`.
## Value objects
- `SecretString` (String/GoString/MarshalJSON/MarshalText/LogValue return `[redacted]`; `Reveal()` explicit).
- `Key`, `SinkSpec{Path, Mode, Owner, Group}`, `CallerInfo{UID, GID, PID, Exe}`.
## Interfaces (domain)
`Signer`, `Provider`, `Deps`, `Clock`, `SecretStore{Get, Put(version)}`, `PeerCredReader`, `Sink`, `AuditSink`, `OktaTokenSource`.
## Enumerations
States: `empty, minting, valid, refreshing, degraded, revoked, reauth_required`. Errors: `ErrTransient, ErrAuthDefinitive, ErrConfig, ErrPolicy, ErrProvider`. Exit codes: 0, 77 revoked, 78 config.
## API types
`GET /v1/credentials/{provider}` -> `{token_type, access_token, issued_at, expires_at, audience}`; `/v1/status`, `/v1/identity`, `/healthz`; error body `{error, state, retry_after_seconds}`. Mirrored in `pkg/client` with golden tests.
## Config
Per PRD section 10 YAML schema.
