# Product details

What the daemon does, as built. Unverified vendor behavior is marked **[UNVERIFIED A-xx]** and refers to [`assumptions.md`](assumptions.md). The original requirements are in `../specs/261003-agent-okta-d/agent-okta-d-PRD.md`.

## Goals and non-goals

Goals: each agent has its own Okta identity; the agent process never handles OIDC, never reads a long-lived secret and never sees a signing key; credentials are short lived, refreshed proactively and fail closed; the daemon is the only holder of key material.

Non-goals: authorization decisions (stay server side), human login, LLM provider credentials, native Windows (WSL2 with the Linux build is the intended route, **[UNVERIFIED A-11]**), an MCP gateway.

## Components

One static Go binary, `agent-okta-d`, is both the daemon (`run`) and the operator CLI. The daemon listens on a unix domain socket only (no network listener), authenticates each caller by peer credentials (uid/gid, supplementary groups, executable path for audit), and serves credentials from an in-memory cache. Authorization to call the API is group based: `ipc.allow_gids` (group names or numeric gids). The daemon must run as a different OS principal from the agent; `doctor` and startup refuse to run when the daemon's primary gid is in `ipc.allow_gids` and warn when running as root.

## Local API

Over the socket, JSON, `Cache-Control: no-store`:

| Request | Meaning |
|---|---|
| `GET /v1/credentials/{provider}` | current credential (refreshes synchronously when near expiry) |
| `POST /v1/credentials/{provider}/refresh` | force a refresh |
| `GET /v1/status` | daemon and per-provider state |
| `GET /v1/identity` | agent id, Okta client id, kid, daemon version, API version `v1` |
| `GET /healthz` | liveness; needs a verified peer, not a gid match |

Error bodies carry an `error` code, which is authoritative over the HTTP status: `reauth_required` 401, `revoked` 403, `unauthorized` 403, `not_configured` 404, `degraded` 503 (with `Retry-After`), `internal` 500. There is no revoke endpoint. The full client side contract is in `technical-details.md`.

## Providers

Provider names used in the API and CLI: `aws`, `github`, `servicenow`, `msgraph`, `atlassian`. A provider exists only when its `providers.<name>` section is configured; otherwise the API answers `not_configured`. A provider that fails its startup self-test with a config, policy or provider error is not registered (404); transient errors and `reauth_required` keep it registered.

- **aws**: mints an Okta access token from the configured authorization server (client credentials with `private_key_jwt`), writes it as the web-identity token file (`providers.aws.token_file`, default mode 0440, raw token plus newline) that the unmodified AWS CLI/SDKs exchange with STS via `AssumeRoleWithWebIdentity`. Refresh at about 50 percent of lifetime (0.45 plus up to 0.05 jitter). `configure aws` and `env aws` print the profile or `AWS_*` lines with `role_session_name` set to the agent id. The STS exchange is done by the AWS tooling, not the daemon. Token lifetime is taken from the response **[UNVERIFIED A-02]**; trust-policy `sub` equals the client id **[UNVERIFIED A-03]**.
- **servicenow**: mints an Okta access token and serves it as a Bearer token. Synchronous refresh when less than `min_ttl_seconds` (default 120) remains.
- **github**: vault and refresher for the agent's GitHub EMU user credential. Modes `pat` (token read from stdin at `enroll github`, optional `--expires`) and `oauth_device` (device flow). The credential is stored through the configured store and served as a static secret. Consumers: `credential-helper github` (git), `env github` (`GH_TOKEN`, or `GH_ENTERPRISE_TOKEN` plus `GH_HOST` for a non-github.com `api_base`), the `gh` shim from `configure gh`, and `configure git` (credential helper, optional `user.name`/`user.email` from `git_identity` or `GET /user` with the noreply address). Expiry warning inside `expiry_warning_days`. PAT expiry header and noreply form **[UNVERIFIED A-05]**; GitHub CLI public OAuth app allowed for EMU **[UNVERIFIED A-06]**.
- **msgraph**: delegated Microsoft Graph access token for the agent user, refreshed from a stored refresh token (device flow at `enroll msgraph`). Every `invalid_grant` variant maps to `reauth_required` **[UNVERIFIED A-07]**; doctor probes that `probe_other_user` is refused.
- **atlassian**: generic secret provider. Re-fetches a secret from `source` every `interval_seconds` (default 900) and renders it to a 0440 file sink for the Rovo MCP client. Only `source: aws-secretsmanager` is accepted, which is not available in this build (see Limitations in `product-summary.md`). Hermes re-reading the file without restart **[UNVERIFIED A-09]**.

## Operator CLI

`agent-okta-d <command>`; common flags `--config FILE` (default `$AGENT_OKTA_D_CONFIG` or `/etc/agent-okta-d/config.yaml`) and `--socket PATH`. Exit codes: 0 ok, 1 failure, 2 usage, 3 daemon unreachable (client commands), 77 revoked, 78 configuration. Commands: `run`, `token <provider> [--format raw|json] [--refresh]`, `status [--json]`, `doctor`, `revoke [--timeout]`, `env aws|github`, `credential-helper github get|store|erase [--login --web-base]`, `configure aws [--env] [--write FILE]`, `configure git [--apply] [--no-identity]`, `configure gh --gh-path PATH [--output FILE]`, `enroll github [--mode --expires]`, `enroll msgraph`, `enroll okta`, `version`. See `user-docs/usage.md` for examples.

## Lifecycle, signals and the kill switch

`SIGTERM`/`SIGINT` stop gracefully (sinks removed, exit 0). `SIGUSR1` starts the revoke sequence. `SIGHUP` is logged and ignored (hot reload is deferred). The revoke sequence: state `revoked` (API answers 403), credential files removed, provider revoke hooks run (best effort; the Okta revoke call **[UNVERIFIED A-04]**), in-memory secrets forgotten, a critical audit event, exit 77. `agent-okta-d revoke` signals the daemon via the pidfile next to the socket (written mode 0640 and replaced at start) and wipes the sinks itself, so it works when the daemon is down. Before signaling it connects to the daemon socket and compares the peer pid with the pidfile; if they differ (a stale pidfile after a crash and PID reuse) it sends no signal, wipes the sinks and exits 1 asking the operator to check manually. The daemon exits 77 when Okta rejects the client itself (`invalid_client` or `unauthorized_client`, confirmed twice within 30 s: app disabled or key removed) so supervisors do not restart-loop. `access_denied` and `invalid_grant` can be a policy or scope denial for one authorization server, so they only back off and degrade that provider **[UNVERIFIED A-20]**. Disabling the Okta app and the agent's user is still a manual operator step. SCIM and Entra propagation delays **[UNVERIFIED A-08]**.

## Delivery state and deferred items

Built: everything marked "Built" in `product-summary.md`; M1 cross-compile (`CGO_ENABLED=0` for darwin/arm64, linux/amd64, linux/arm64) is checked by tests and CI.

Deferred, with rationale:

| Item | Rationale |
|---|---|
| M0 spikes (A-01 to A-12 and A-20) | Need real tenants and hardware; replaced by `m0-spike-checklist.md`, to be run by humans |
| M6 Okta roadmap evaluation | Research task about vendor roadmap, not code; out of scope for this build |
| Entra Agent User spike | Requires a real Entra tenant; out of scope |
| AWS SDK adapters (KMS, Secrets Manager, STS), FR-R01 | No SDK dependency was added (offline, fakes-only build); blocks `kms` signer, `aws-secretsmanager` store, `atlassian` provider and the AWS doctor probe. Follow-up task |
| Keychain / Secure Enclave and TPM 2.0 hardware backends, native Keychain store | Need hardware, cgo/vendor tooling and a macOS runner **[UNVERIFIED A-12]**; stubs fail closed with exit 78 |
| P1/P2 items: FR-12 metrics, FR-13 hot reload, FR-14 memory hygiene, GH-10/11/12, MG-7/8, AT-2c, AWS-6, SN-5 | Not trivial; not implemented |
| ES256 | Implemented and flagged; Okta acceptance unconfirmed **[UNVERIFIED A-01]**, RS256 is the default |
| KMS DER to JOSE conversion | Unit tested with vectors only **[UNVERIFIED A-10]** |
| Root-repo skill update (`skills/agent-okta-d.md`) | Separate manual PR in the agentic-teams repo |
| Release workflows (build, sign, notarize, publish) | Not part of this work; only CI exists |
