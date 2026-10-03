# Technical details

Design and reference for what is built. Requirements: `../specs/archive/261003-agent-okta-d/agent-okta-d-PRD.md`. Unverified vendor behavior is marked **[UNVERIFIED A-xx]** (see `assumptions.md`).

## Architecture

Clean Architecture: `internal/domain` (stdlib only) defines every contract; adapters depend inward; all wiring is in `internal/app`, which `cmd/agent-okta-d` calls with `app.DefaultEnv()`. Every external seam (clock, HTTP, sinks, peer credentials, KMS, Secrets Manager, STS, signals, process identity, exec) is a field of `app.Env`, so the whole daemon runs end to end against fakes.

```
config -> signer -> okta token source -> cache -> providers -> sink -> ipc -> obs
```

Packages: `internal/config` (YAML, strict, defaults), `signer/{file,kms,keychain,tpm}`, `okta` (private_key_jwt assertions, token endpoint, clock-skew check), `cache` (state machine, scheduler, single flight), `provider/{aws,github,servicenow,msgraph,secret}`, `store/{encfile,awssm,keychain}`, `enroll/{github,msgraph}`, `ipc` (unix socket server, peer credentials with build-tagged `linux`/`darwin` code), `sink` (atomic 0440 file writes, stale wipe), `obs` (redacting logger, audit), `app` (wiring and CLI), `version`.

Cache states: `empty`, `minting`, `valid`, `refreshing`, `degraded`, `revoked`, `reauth_required`. Refresh fraction, jitter and `min_margin_seconds` come from `refresh.*`; the AWS provider uses a fixed 0.45 fraction plus at most 0.05 jitter; ServiceNow refreshes synchronously below `min_ttl_seconds`.

## Signers and stores in this build

| Component | Works in the shipped binary | Notes |
|---|---|---|
| signer `file` | yes | PEM PKCS#8, PKCS#1 RSA or SEC1 P-256; refuses a key file with any group/other permission bits (`ErrPolicy`); RSA at least 2048 bits; development use |
| signer `kms` | no | `kms` package and DER to JOSE conversion exist and are unit tested **[UNVERIFIED A-10]**; no `KMSAPI` implementation, so startup exits 78 |
| signer `keychain` | no | `Open` returns `ErrConfig` ("not implemented in this build") on darwin, "unsupported" elsewhere **[UNVERIFIED A-12]** |
| signer `tpm` | no | same, on linux **[UNVERIFIED A-12]** |
| store `file-encrypted` | yes | encrypted file, key derived from a deterministic RS256 signature over a fixed label; ES256 signers are refused for this store; path `store.path`, default `/var/lib/agentd/<id>/secrets.enc` (`/var/db/agentd/<id>` on macOS) |
| store `aws-secretsmanager` | no | `awssm` adapter exists against an interface; no `SecretsManagerAPI` implementation |
| store `keychain` | no | `NewNative` returns `ErrConfig` |

## Configuration reference (summary)

The authoritative field list with defaults and validation is `user-docs/configuration.md`, which mirrors `internal/config`. Unknown YAML fields are rejected; errors name the field path and never echo values; every failure is `ErrConfig` (exit 78).

## Error taxonomy and exit codes

`ErrTransient`, `ErrAuthDefinitive` (only Okta definitive rejections), `ErrConfig`, `ErrPolicy`, `ErrProvider`, `ErrReauthRequired`, `ErrRevoked`, `ErrNotFound`, `ErrVersionConflict`. Exit codes: 0 ok, 1 failure, 2 usage, 3 daemon unreachable, 77 revoked, 78 configuration. A policy error (for example daemon gid in `ipc.allow_gids`, key file permissions) exits 1.

## Revocation and exposure windows

Revoke order (proven by a test): revoked state, sinks removed, provider revoke hooks, forget in-memory secrets, critical audit event, exit 77. Credentials already issued stay valid until their own expiry; Okta token revocation for client-credential tokens is best effort **[UNVERIFIED A-04]**; SCIM/Entra propagation delays are unmeasured **[UNVERIFIED A-08]**.

## pkg/client reference

Import path `github.com/stainedhead/agent-okta-d/pkg/client`. Standard library only; never imports `internal/`. Safe for concurrent use. The wire types are deliberately duplicated from `internal/domain/wire.go` and both are pinned to golden JSON (`internal/domain/testdata/wire`, `pkg/client/testdata`).

**Stability promise.** The exported surface of `pkg/client` and `pkg/client/clienttest` is snapshotted in `pkg/client/testdata/api.txt` and a test (`TestExportedAPISnapshot`) fails on any change, forcing a deliberate semver decision. Wire field names and error codes are frozen for API version `v1`; changes to the wire contract touch both type copies and the goldens. Unknown `State` values from a newer daemon are passed through unchanged, so compare against the constants instead of switching exhaustively. The module is pre-1.0 (`0.0.0-dev` unless stamped); no release has been cut, and release workflows are not part of this work.

### Constants

| Identifier | Value |
|---|---|
| `EnvSocket` | `"AGENT_OKTA_D_SOCKET"` |
| `DefaultTimeout` | `5 * time.Second` |
| `Redacted` | `"[redacted]"` |
| `StateEmpty`, `StateMinting`, `StateValid`, `StateRefreshing`, `StateDegraded`, `StateRevoked`, `StateReauthRequired` (type `State`) | `"empty"`, `"minting"`, `"valid"`, `"refreshing"`, `"degraded"`, `"revoked"`, `"reauth_required"` |

### Functions and options

- `func New(opts ...Option) *Client`: socket path is, in order, `WithSocketPath`, `$AGENT_OKTA_D_SOCKET`, `DefaultSocketPath()`.
- `type Option func(*Client)`; `func WithSocketPath(path string) Option`; `func WithTimeout(d time.Duration) Option` (per request; values <= 0 ignored).
- `func DefaultSocketPath() string`: `/var/run/agentd/agentd.sock` on darwin, `/run/agentd/agentd.sock` otherwise; does not read the environment. **Discrepancy:** the daemon's default `ipc.socket` is `/run/agentd/<agent.id>/agentd.sock` (`/var/run/agentd/<agent.id>/agentd.sock` on macOS), one directory deeper, so a client with no option and no environment variable reaches a default-configured daemon only if the config sets `ipc.socket` to the client default. The file name `agentd.sock` is itself an assumption proposed in code as "A-13" but not yet in `assumptions.md`.
- `func RetryAfter(err error) (time.Duration, bool)`: the retry hint carried by an `*APIError`, if positive.
- `func NewSecret(v string) Secret`.

### Client methods

All take a `context.Context`; each call is bounded by the client timeout.

- `func (c *Client) Credential(ctx, provider string) (Credential, error)`: `GET /v1/credentials/{provider}`. An empty provider returns an error wrapping `ErrNotConfigured` without a request. A 2xx body with an empty `access_token` returns `ErrInvalidResponse`.
- `func (c *Client) Refresh(ctx, provider string) (Credential, error)`: `POST /v1/credentials/{provider}/refresh`.
- `func (c *Client) Status(ctx) (Status, error)`: `GET /v1/status`.
- `func (c *Client) Identity(ctx) (Identity, error)`: `GET /v1/identity`.
- `func (c *Client) SocketPath() string`; `func (c *Client) Close()` (releases idle connections; the client stays usable).

### Wire types

JSON shapes (golden tested):

```
Credential  {"token_type","access_token","issued_at","expires_at","audience"}
Status      {"state","providers":[ProviderStatus]}
ProviderStatus {"provider","state","expires_at"?,"last_error"?,"retry_after_seconds"?}
Identity    {"agent_id","okta_client_id","kid","daemon_version","api_version"}
error body  {"error","state"?,"retry_after_seconds"?}
```

- `type Credential struct { TokenType string; AccessToken Secret; IssuedAt, ExpiresAt time.Time; Audience string }` with `ExpiredAt(t time.Time) bool` (true when `t` is not before `ExpiresAt`) and `String()` (never includes the token). `TokenType` is `"Bearer"` for bearer credentials, otherwise the credential kind.
- `type ProviderStatus struct { Provider string; State State; ExpiresAt *time.Time; LastError string; RetryAfterSeconds int }` (`LastError` is an error class, never a message).
- `type Status struct { State State; Providers []ProviderStatus }`.
- `type Identity struct { AgentID, OktaClientID, KID, DaemonVersion, APIVersion string }`.
- `type Secret struct{ ... }` (opaque): `Reveal() string` returns the raw value (use only at the point of use); `IsZero() bool`; `String`, `GoString`, `Format` (all verbs), `MarshalJSON`, `MarshalText` and `LogValue` (slog) all render `[redacted]`; `UnmarshalJSON` decodes a JSON string into it. Re-marshaling a `Credential` therefore never leaks the token.

### Errors

Sentinels (match with `errors.Is`): `ErrReauthRequired` (401), `ErrRevoked` (403), `ErrDegraded` (503), `ErrUnauthorized` (403), `ErrNotConfigured` (404), `ErrDaemonUnavailable` (socket unreachable, request timeout, I/O failure), `ErrInvalidResponse` (undecodable or empty answer; fail closed, no data returned). A canceled context returns `context.Canceled` unchanged.

`type APIError struct { Status int; Code string; State State; RetryAfter time.Duration }` is returned for every non-2xx answer (`Error()`, and `Is(target)` mapping to the sentinel). Mapping: the body `error` code decides first (`reauth_required`, `revoked`, `degraded`, `unauthorized`, `not_configured`), then the HTTP status (401, 403, 404, 503); a bare 403 is `ErrUnauthorized` (fail closed). Any other status, such as 500 `internal`, yields an `*APIError` that matches no sentinel: use `errors.As`. `RetryAfter` comes from the body `retry_after_seconds`, else the `Retry-After` header.

### pkg/client/clienttest

In-process fake daemon on a temporary unix socket, for consumer tests. Exported: constants `CodeReauthRequired`, `CodeRevoked`, `CodeDegraded`, `CodeUnauthorized`, `CodeNotConfigured`, `CodeInternal`; `type TB interface { Helper(); Fatalf(format string, args ...any); Cleanup(func()) }`; types `Credential`, `ProviderStatus`, `Status`, `Identity` (same JSON as the wire types but plain strings, the token is a `string`), `Error{Code, State string; RetryAfter time.Duration; HTTPStatus int}`, `Request{Method, Path string}`, `Server`; `func New(t TB) *Server` (default: every provider answers `not_configured`, empty valid status, placeholder identity; closed automatically at test end); `func DeadSocketPath(t TB) string`; methods `SocketPath`, `Close`, `SetCredential`, `SetRefreshed`, `SetProviderError`, `SetGlobalError`, `SetRaw`, `SetStatus`, `SetIdentity`, `SetDelay`, `Requests`. `clienttest` is part of the snapshot and carries the same stability promise.

## Shared contracts (frozen by WS-0)
`internal/domain` is the single source for: `Credential`, `SecretString`, `Key`, `CacheEntry`, `State` and `CanTransition`, the error taxonomy (`ErrTransient`, `ErrAuthDefinitive`, `ErrConfig`, `ErrPolicy`, `ErrProvider`, plus `ErrReauthRequired`, `ErrRevoked`, `ErrNotFound`, `ErrVersionConflict`), exit codes (0, 77, 78), `AuditEvent`, `Scrubber`, the daemon-side wire types (`Wire*`, error codes, `HTTPStatus`) and the interfaces `Clock`, `Signer`, `Provider`, `Deps`, `OktaTokenSource`, `SecretStore`, `Sink`, `PeerCredReader`, `AuditSink`. Fakes for all of them: `internal/domain/domaintest`. Wire JSON goldens: `internal/domain/testdata/wire`. Conventions every workstream follows: a provider returns `ErrReauthRequired` for an expired user credential and never retries it; only Okta definitive errors are `ErrAuthDefinitive`; secrets cross package boundaries as `SecretString`; `Credential.Validate()` must pass before anything is cached or served.
