# Intent

## Purpose
Use Okta to **secure access to the key tooling given to agentic teammates**, so that an autonomous
agent can work inside the enterprise's systems without ever holding a long-lived secret. This
repository is the credential daemon (`agent-okta-d`, "the daemon") that does that job.

**The wider project.** An agentic teammate is an autonomous SDLC agent that works alongside people
as a real member of the team. It runs inside Hermes, or inside a CLI harness we provide, and the
harness images come from [`agentic-team-w-paperclip`](https://github.com/stainedhead/agentic-team-w-paperclip).
The Go tools in this set exist so those teammates can safely reach the key systems: AWS, GitHub,
ServiceNow, Microsoft 365 (Outlook, Teams) and Atlassian. The set is mapped in
[`agentic-teams`](https://github.com/stainedhead/agentic-teams).

**This tool's role.** The daemon is deployed to the machine or container the agent identity runs
inside. It holds a key the agent can never read, authenticates to Okta, and turns the resulting
short-lived tokens into the credential forms each target's stock tooling already understands. The
agent process never handles OIDC, never reads a long-lived secret and never sees a signing key.

**Why identity is per agent.** Each agent is its own named identity (one Okta application per
agent, no shared client), carried through to its own AWS session, GitHub account, ServiceNow user and
Entra user. Every action is therefore attributable to exactly one agent, and one agent can be cut
off without touching the others.

## Where this fits
```
agent host: harness (Hermes / CLI) in a container -> daemon + CLIs -> Okta -> AWS / GitHub / ServiceNow / M365 / Atlassian
```
| Repository | Relationship to the daemon |
|---|---|
| [`agentic-teams`](https://github.com/stainedhead/agentic-teams) | The root map of the set. Describes this repo's place; holds no code. |
| [`agentic-team-w-paperclip`](https://github.com/stainedhead/agentic-team-w-paperclip) | Provides the harness images the agent runs in. The daemon is deployed beside the agent on that host. |
| [`snow-cli`](https://github.com/stainedhead/snow-cli) | `snow` (ServiceNow). Gets its Okta token from the daemon. Also defines the shared CLI core. |
| [`outlook-cli`](https://github.com/stainedhead/outlook-cli) | `outlook` (mail as the agent's Entra user). Gets a delegated Graph token from the daemon. |
| [`teams-cli`](https://github.com/stainedhead/teams-cli) | `teams` (Teams as the agent's Entra user). Gets a delegated Graph token from the daemon. |

Stock tools (`aws`, `git`, `gh`) stay unmodified and are fed through their native credential
mechanisms. The CLIs reach the daemon through the Go client library planned here (`pkg/client`).
Where the shared CLI core (`agent-cli-core`) will live is an open question and is not decided here.

## Goals
- **No long-lived secret is readable by the agent's OS user.** The daemon and the agent run as
  different OS principals; otherwise the other controls are moot.
- **Per-agent identity end to end**, so every action is attributable to one agent.
- **Invisible refresh.** The agent never handles expiry.
- **Stock tools stay stock.** One implementation of Okta/OIDC logic lives in the daemon.
- **Fail closed, and be auditable.** Disabling an agent withdraws its access, and every mint,
  refresh, serve and revoke is logged without logging secrets. Exposure windows differ by system
  and are documented in the PRD.

## Non-goals
- **Authorization decisions.** These stay server side (IAM, GitHub rulesets, ServiceNow roles/ACLs,
  Atlassian permissions, Exchange/Teams policy). The daemon only obtains credentials.
- **Human login.** The daemon serves agents only.
- **Model-provider (LLM) credentials**, **Windows hosts** (v1) and an **MCP gateway/proxy**.
- **The CLIs, the harness images or the fleet.** Those belong to the sibling repositories and to
  whoever deploys the agents.

## Status and caution
No code exists yet: this repository holds the draft PRD (v0.2) and a scaffold. Several provider
details are marked unconfirmed (the PRD's warning-sign items, for example ES256 key acceptance,
SCIM deprovisioning timing and Okta token revocation behavior). They are assumptions to validate in
a sandbox, not facts, and milestone M0 exists to settle them.

## Scope boundary in one line
> This repository is the credential broker beside each agent, not the agent, its harness, the
> tools it calls or the policy that decides what it may do.

## How this file is used
INTENT.md records *why* this tool exists and what it is aiming at. The *how* and *what* live in
[`agent-okta-d-PRD.md`](agent-okta-d-PRD.md) (source of truth) and `docs/`. Update this file when
goals, direction or scope shift, not when implementation details change.
