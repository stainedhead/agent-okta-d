# agent-okta-d

A credential daemon that gives autonomous SDLC agents short-lived, per-agent access to AWS, GitHub, ServiceNow, Atlassian and Microsoft 365 (Outlook, Teams), rooted in Okta OIDC where the target system accepts it.

**Status: Draft PRD (v0.2). No implementation yet.** The requirements are in [`agent-okta-d-PRD.md`](agent-okta-d-PRD.md).

## What it is

`agent-okta-d` ("the daemon") runs beside each agent host (desktop or cloud). It authenticates to Okta with a private key the agent can never read, obtains short-lived OIDC tokens, and converts them into the credential forms that each downstream system's stock tooling already understands:

- AWS: a web-identity token file, consumed by the unmodified `aws` CLI.
- GitHub: a git credential helper and `GH_TOKEN` for the agent's GitHub Enterprise Managed User account.
- ServiceNow: a Bearer token for the `snow` CLI.
- Atlassian: a secret for the Rovo MCP client.
- Microsoft 365: a delegated Graph token for the `outlook` and `teams` CLIs.

## Why

Agents are LLM-driven processes with a shell. They should never handle OIDC, read a long-lived secret or see a signing key, yet every action should be attributable to exactly one agent. Keeping all Okta/OIDC logic in one daemon lets `aws`, `gh` and `git` stay unmodified.

## Key design points

- Okta OIDC is the identity root. Each agent is a workload identity: one Okta application per agent, authenticated with `private_key_jwt` client credentials. No shared client.
- Where the target accepts Okta tokens (AWS, ServiceNow) the daemon mints them directly. Where it does not (GitHub, Microsoft 365, Atlassian) the agent is a real user account and the daemon acts as vault and refresher for that account's credential, kept behind the Okta-federated role where possible.
- The daemon and the agent run as different OS principals. If they share a user, the other controls are moot. Key custody varies by topology: AWS KMS in the cloud, Keychain on macOS, TPM or a protected key file on Linux.
- Local API over a unix domain socket with peer-credential authentication; no network listeners.
- Credentials refresh proactively, fail closed, and are logged and audited with a redaction layer so no secret is logged.
- The kill switch has two parts: disable the agent's Okta application and disable the agent's user account. Credentials already issued live until their own expiry, so exposure windows are documented per system (PRD section 13).
- Authorization is never decided by the daemon; it stays server side (IAM, GitHub rulesets, ServiceNow roles/ACLs, Atlassian permissions, Exchange/Teams policy).
- Planned in Go (static binary, macOS and Linux; Windows is out of scope for v1).

## Evidence caveats

The PRD marks each claim with an evidence legend: a check mark means confirmed against vendor documentation during research on 2026-10-03; a warning sign means not confirmed (community source, third-party doc or engineering judgment) and must be validated in a sandbox before anything depends on it. Many provider details are still unconfirmed, for example Okta acceptance of ES256 keys from the Secure Enclave, the timing of SCIM deprovisioning to GitHub, Microsoft Graph refresh-token lifetime under Conditional Access, and Okta token revocation behavior. Milestone M0 exists to confirm or change these assumptions. Treat this README as a summary and the PRD as authoritative.

## Companion repositories

This repository is one of a set of related projects:

- [`snow-cli`](https://github.com/stainedhead/snow-cli): the ServiceNow CLI and the shared CLI core.
- [`outlook-cli`](https://github.com/stainedhead/outlook-cli): agent-safe Outlook mail access.
- [`teams-cli`](https://github.com/stainedhead/teams-cli): agent-safe Microsoft Teams access.
- [`agentic-team-w-paperclip`](https://github.com/stainedhead/agentic-team-w-paperclip): part of the set rooted at [`agentic-teams`](https://github.com/stainedhead/agentic-teams).

The `snow`, `outlook` and `teams` CLIs obtain their credentials from this daemon (via the Go client library planned in `pkg/client`).

## Planned layout

```
cmd/agent-okta-d/   subcommands, signal handling, exit codes
internal/           config, signer, okta, provider, store, enroll, cache, ipc, sink, obs
pkg/client/         Go client library used by the snow, outlook and teams CLIs
docs/               product and technical documentation
user-docs/          end-user documentation (install, configure, use, troubleshoot)
specs/              feature specs (completed specs in specs/archive/)
```

None of the code directories exist yet. See PRD section 9 for the full module layout and interfaces.

## Documentation

- [`agent-okta-d-PRD.md`](agent-okta-d-PRD.md): the product requirements document (source of truth).
- [`docs/`](docs/): product summary, product details, technical details and architectural decision record.
- [`user-docs/`](user-docs/): end-user documentation; nothing to read yet.
- [`AGENTS.md`](AGENTS.md): contributor and agent rules.

## Contributing

See [`AGENTS.md`](AGENTS.md). Before committing run `gofmt -l .`, `go vet ./...`, `golangci-lint run` and `go test ./...`. Never commit credentials.
