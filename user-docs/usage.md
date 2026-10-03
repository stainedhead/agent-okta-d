# Usage examples

Client commands (`token`, `status`, `env github`, `credential-helper`, `configure git`) talk to the daemon socket: pass `--socket PATH` or set `AGENT_OKTA_D_SOCKET`. Commands that read configuration take `--config FILE`. Exit codes: 0 ok, 1 failure, 2 usage, 3 daemon unreachable, 77 revoked, 78 configuration.

Everything below was exercised against fakes only; vendor-side behavior is **UNVERIFIED** unless stated (see `../docs/assumptions.md`).

## Daemon lifecycle

```
agent-okta-d run --config /etc/agent-okta-d/config.yaml     # as the daemon user
agent-okta-d doctor --config /etc/agent-okta-d/config.yaml  # self-test with provider probes
agent-okta-d version
```

Signals: `SIGTERM`/`SIGINT` stop gracefully and remove credential files; `SIGUSR1` revokes (exit 77); `SIGHUP` is logged and ignored (no hot reload: restart to apply config changes).

## status and token

```
agent-okta-d status            # human readable; exit 0 only when everything is valid
agent-okta-d status --json     # {"status":{...},"identity":{...}}
agent-okta-d token servicenow                 # prints the raw token and newline
agent-okta-d token servicenow --format json   # token_type, access_token, issued_at, expires_at, audience
agent-okta-d token github --refresh           # force a refresh first
```

`status` exits non-zero when the daemon is not valid, when it is revoked (77), or when any provider is `degraded` or `reauth_required`. `token` prints the real secret on purpose; do not log its output.

## aws

Config: `providers.aws` (see the configuration reference). The daemon keeps the Okta token fresh in `token_file`; the stock AWS CLI exchanges it with STS (**UNVERIFIED**: the trust policy condition on `sub`, A-03, and the Okta token lifetime, A-02).

```
agent-okta-d configure aws --config CFG                     # print [profile agent]
agent-okta-d configure aws --config CFG --write ~/.aws/config   # append it (refuses if [profile agent] exists)
agent-okta-d configure aws --config CFG --env               # export AWS_ROLE_ARN, AWS_WEB_IDENTITY_TOKEN_FILE, ...
agent-okta-d env aws --config CFG
aws --profile agent sts get-caller-identity
```

`doctor` cannot run the AWS probe in this build (no STS client).

## github

Config: `providers.github` with a `file-encrypted` store. Enroll once as the operator (the enrolled credential is stored encrypted and never given to the agent directly):

```
# PAT mode: the PAT is read from stdin
printf '%s' "$PAT" | agent-okta-d enroll github --config CFG --expires 2027-01-31
# device flow mode: follow the printed instructions
agent-okta-d enroll github --config CFG
```

Use from the agent:

```
agent-okta-d configure git --config CFG            # print git config (credential helper + identity)
agent-okta-d configure git --config CFG --apply    # run git config --system
agent-okta-d configure git --config CFG --no-identity
eval "$(agent-okta-d env github --config CFG)"     # GH_TOKEN (or GH_ENTERPRISE_TOKEN + GH_HOST)
agent-okta-d configure gh --gh-path /usr/bin/gh --output /usr/local/bin/gh
```

`configure gh` writes a shim that fetches the token per invocation and execs the real `gh`. The git credential helper protocol is `agent-okta-d credential-helper github get|store|erase [--login NAME --web-base URL]`; `store` and `erase` do nothing useful by design. When a PAT or refresh credential expires, the daemon reports `reauth_required`: run `agent-okta-d enroll github` again. PAT expiry header, noreply address form and the public OAuth app policy are **UNVERIFIED** (A-05, A-06).

## servicenow

```
agent-okta-d token servicenow     # Bearer token for the snow CLI
```

The `snow` CLI normally reaches the daemon through the shared CLI core library rather than this command.

## msgraph (Outlook, Teams)

Enroll the agent user once (device-code flow; the signed-in UPN must equal `providers.msgraph.upn`):

```
agent-okta-d enroll msgraph --config CFG
agent-okta-d token msgraph
```

If Conditional Access, a password reset or token revocation invalidates the refresh token the provider reports `reauth_required`; enroll again. Refresh rotation and invalidation behavior are **UNVERIFIED** (A-07). The `outlook` and `teams` CLIs get the token via the shared CLI core.

## atlassian

Cannot start in this build (requires the `aws-secretsmanager` source, which has no adapter). When available it writes the secret to `providers.atlassian.sink.file` (0440) for the Rovo MCP client; whether Hermes re-reads it without restart is **UNVERIFIED** (A-09).

## Revoke (kill switch)

```
agent-okta-d revoke --config CFG [--timeout 15s]
```

Signals the running daemon (via the pidfile next to the socket), waits for it to exit 77, and removes the credential files itself, so it also works with the daemon down. It does NOT disable anything in Okta or the identity provider: afterwards disable the agent's Okta app, then the agent's user. Already issued credentials stay valid until they expire; Okta revocation of issued tokens is best effort and **UNVERIFIED** (A-04), and SCIM/Entra propagation delays are unmeasured (A-08).

## enroll okta

```
agent-okta-d enroll okta --config CFG    # prints the JWK and the Okta onboarding checklist
```
