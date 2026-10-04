# agent-okta-d

A credential daemon that gives autonomous SDLC agents short-lived, per-agent access to AWS, GitHub, ServiceNow, Atlassian and Microsoft 365 (Outlook, Teams), rooted in Okta OIDC where the target system accepts it.

**Status: implemented and tested against fakes only; never run against a real tenant.** The requirements are in [`specs/archive/261003-agent-okta-d/agent-okta-d-PRD.md`](specs/archive/261003-agent-okta-d/agent-okta-d-PRD.md). For why this exists and how it fits the wider agentic-teams project, see [`INTENT.md`](INTENT.md).

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
- Written in Go (static binary, macOS and Linux; native Windows is not a target; Windows machines use WSL2 with the Linux build).

## Evidence caveats

The PRD marks each claim with an evidence legend: a check mark means confirmed against vendor documentation during research on 2026-10-03; a warning sign means not confirmed (community source, third-party doc or engineering judgment) and must be validated in a sandbox before anything depends on it. Many provider details are still unconfirmed, for example Okta acceptance of ES256 keys from the Secure Enclave, the timing of SCIM deprovisioning to GitHub, Microsoft Graph refresh-token lifetime under Conditional Access, and Okta token revocation behavior. Milestone M0 exists to confirm or change these assumptions. Treat this README as a summary and the PRD as authoritative.

## Companion repositories

This repository is one of a set of related projects:

- [`snow-cli`](https://github.com/stainedhead/snow-cli): the ServiceNow CLI, built on the shared CLI core.
- [`agent-cli-core`](https://github.com/stainedhead/agent-cli-core): the shared CLI core library; its `auth` package wraps this repo's `pkg/client`.
- [`outlook-cli`](https://github.com/stainedhead/outlook-cli): agent-safe Outlook mail access.
- [`teams-cli`](https://github.com/stainedhead/teams-cli): agent-safe Microsoft Teams access.
- [`agentic-team-w-paperclip`](https://github.com/stainedhead/agentic-team-w-paperclip): part of the set rooted at [`agentic-teams`](https://github.com/stainedhead/agentic-teams).

The `snow`, `outlook` and `teams` CLIs obtain their credentials from this daemon through [`agent-cli-core`](https://github.com/stainedhead/agent-cli-core), whose `auth` package is the consumer of the Go client library in `pkg/client`.

## What is built, and what is not

Built and fake-tested: the daemon (`run`), unix-socket API with peer-credential auth, cache and refresh scheduler, file sinks, redacting logs and audit, the `aws`, `github`, `servicenow`, `msgraph` and `atlassian` provider code, the operator CLI (`run`, `token`, `status`, `doctor`, `revoke`, `env`, `credential-helper`, `configure aws|git|gh`, `enroll github|msgraph|okta`, `version`), and the `pkg/client` library with its `clienttest` fake daemon.

Not usable in the shipped binary: the `kms`, `keychain` and `tpm` signers, the `aws-secretsmanager` and `keychain` stores, and therefore the `atlassian` provider and the AWS `doctor` probe (the AWS SDK adapters and hardware backends are deferred; a config needing them exits 78). The only working signer is `file` (development use) and the only working store is `file-encrypted`.

Unverified: all vendor behavior listed in [`docs/assumptions.md`](docs/assumptions.md) (A-01 to A-12 and A-20). The real-tenant M0 spikes are replaced by [`docs/m0-spike-checklist.md`](docs/m0-spike-checklist.md) and have not been run. Also deferred: M6 Okta roadmap evaluation, the Entra Agent User spike, P1/P2 items (metrics, hot reload, memory hygiene, GH-10/11/12, MG-7/8, AT-2c, AWS-6, SN-5). Release workflows (build, sign, notarize, publish) are not part of this work; only CI exists. Deferred items, the unverified list and the pending root skill update: [`docs/deferred.md`](docs/deferred.md). Details: [`docs/product-details.md`](docs/product-details.md).

## Layout

```
cmd/agent-okta-d/   entry point (calls internal/app)
internal/           app, cache, config, domain, enroll, ipc, obs, okta, provider, signer, sink, store, version
pkg/client/         Go client library consumed by agent-cli-core's auth package (+ clienttest fake daemon)
docs/               product and technical documentation
user-docs/          end-user documentation (install, configure, use, troubleshoot)
specs/              feature specs (completed specs in specs/archive/)
```

## Quick start

```
make build && ./bin/agent-okta-d --help
```

Then follow [`user-docs/getting-started.md`](user-docs/getting-started.md).

## Documentation

User documentation (adopt, configure, use):

- [`user-docs/getting-started.md`](user-docs/getting-started.md)
- [`user-docs/configuration.md`](user-docs/configuration.md): configuration reference
- [`user-docs/usage.md`](user-docs/usage.md): examples for every command and provider
- [`user-docs/client-library.md`](user-docs/client-library.md): using `pkg/client`
- [`user-docs/troubleshooting.md`](user-docs/troubleshooting.md)

Project documentation:

- [`INTENT.md`](INTENT.md): purpose, wider context, goals and scope.
- [`specs/archive/261003-agent-okta-d/agent-okta-d-PRD.md`](specs/archive/261003-agent-okta-d/agent-okta-d-PRD.md): the product requirements document (source of truth).
- [`docs/product-summary.md`](docs/product-summary.md), [`docs/product-details.md`](docs/product-details.md), [`docs/technical-details.md`](docs/technical-details.md) (includes the full `pkg/client` reference), [`docs/architectural-decision-record.md`](docs/architectural-decision-record.md), [`docs/assumptions.md`](docs/assumptions.md), [`docs/m0-spike-checklist.md`](docs/m0-spike-checklist.md), [`docs/deferred.md`](docs/deferred.md).
- [`AGENTS.md`](AGENTS.md): contributor and agent rules.

## Contributing

See [`AGENTS.md`](AGENTS.md). Before committing run `gofmt -l .`, `go vet ./...`, `golangci-lint run` and `go test ./...`. Never commit credentials.

## License

MIT. See [LICENSE](LICENSE).
