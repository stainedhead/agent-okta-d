# Troubleshooting

## Exit codes

| Code | Meaning | What to do |
|---|---|---|
| 0 | success | |
| 1 | failure (transient, provider, policy, degraded, not valid) | read the message; retry if `degraded` |
| 2 | usage error | check flags and arguments |
| 3 | daemon unreachable (client commands) | start the daemon; check the socket path and that your user is in a group listed in `ipc.allow_gids` |
| 77 | revoked | the daemon was revoked or Okta rejected the app/key. Do not restart-loop. Fix the cause in Okta, then start again |
| 78 | configuration error | the message names the field; fix the config |

## Common messages

- `403 unauthorized` on Linux although the agent is in an allowed group: the daemon reads supplementary groups from `/proc/<pid>/status`; if `/proc` is mounted with `hidepid` only the primary gid is checked. Make the allowed group the agent's primary group or relax `hidepid` for the daemon.
- `socket directory ... is accessible to other users` / `owned by uid`, exit 77: `chown` the socket directory to the daemon user and `chmod 0750` (or tighter).
- `the agent-okta-d daemon is unreachable (is it running, and is this user in ipc.allow_gids?)`: wrong socket (set `AGENT_OKTA_D_SOCKET` or `--socket`; the client default differs from the daemon's per-agent default), daemon not running, or the socket directory is not traversable by your group.
- `<provider> needs re-enrollment: run agent-okta-d enroll <provider>`: the stored user credential expired or was invalidated (state `reauth_required`).
- `<provider> is degraded, retry in Ns`: upstream failing; the daemon retries with backoff. Check `status` for `last_error`.
- `... is not available in this build (no AWS SDK adapter)`, exit 78: the config uses the `kms` signer, the `aws-secretsmanager` store or the `atlassian` provider. These cannot run in this build; use the `file` signer and the `file-encrypted` store.
- `macOS Keychain / Secure Enclave backend not implemented in this build` / `Linux TPM 2.0 backend not implemented in this build`: hardware signers are not implemented. Use `file`.
- `the daemon's primary gid N is listed in ipc.allow_gids`: run the daemon as its own user and group, separate from the agent.
- `okta-clock-skew` fail: the host clock is 30 seconds or more away from Okta; fix time sync.
- Key file refused: the PEM file must be a regular file with no group or other permission bits (`chmod 0400`), RSA at least 2048 bits, and match `okta.signer.alg`.
- `file-encrypted needs an RS256 signer`: the encrypted store cannot be used with an ES256 signer.
- Unknown field errors: the config parser rejects keys it does not know; check spelling against the configuration reference.
- `doctor` msgraph probe config failure: set `providers.msgraph.probe_other_user`.
- `doctor` AWS probe fails with "no STS client configured": expected in this build.
- `configure gh` says `--gh-path ... is required`: pass the absolute path of the real `gh`.
- `credential-helper` cannot read the config: it runs as the agent user, so make the config readable by it (it holds no secrets) or pass `--login` and `--web-base`.

## Vendor behavior that may differ from expectations

These behaviors were never confirmed against a real tenant (see `../docs/assumptions.md`): Okta acceptance of ES256 assertions (A-01), minimum access-token lifetime (A-02), `sub` of client-credential tokens (A-03), Okta revocation of issued tokens (A-04), GitHub PAT expiry header and noreply email form (A-05), the GitHub CLI OAuth app for EMU users (A-06), Microsoft Graph refresh and Conditional Access behavior (A-07), deprovisioning delays (A-08), Hermes reloading MCP secrets (A-09), KMS signature conversion (A-10), WSL2 service support (A-11), macOS notarization and cgo for Keychain (A-12). If something behaves differently from these guides, a failed assumption is the first suspect.
