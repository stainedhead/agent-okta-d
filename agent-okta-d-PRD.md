# agent-okta-d — Product Requirements Document

| | |
|---|---|
| **Status** | Draft v0.2 |
| **Date** | 2026-10-03 |
| **Owner** | Enterprise Architecture (owner TBD) |
| **Companion docs** | `agent-cli-core-PRD.md` (the shared CLI core library, own repo: https://github.com/stainedhead/agent-cli-core), `snow-cli-PRD.md` (ServiceNow CLI), `outlook-cli-PRD.md`, `teams-cli-PRD.md` |
| **Scope** | Credential daemon that gives autonomous SDLC agents (each a named user account) access to AWS, GitHub, ServiceNow, Atlassian and Microsoft 365 (Outlook, Teams), rooted in Okta OIDC where the target system accepts it |

**Evidence legend.** ✅ = confirmed against vendor documentation during research for this PRD (2026-10-03). ⚠️ = not confirmed in vendor docs this session (community source, third-party doc, or engineering judgment). Validate every ⚠️ item in a sandbox before depending on it.

---

## 1. Summary

`agent-okta-d` ("the daemon") runs beside each agent host (desktop or cloud). It authenticates to Okta with a private key the agent can never read, obtains short-lived OIDC tokens, and converts them into the credential forms that each downstream system's **stock tooling already understands** (AWS web-identity token file, git credential helper and `GH_TOKEN` for the agent's GitHub EMU account, Bearer token for the `snow` CLI, a secret for the Atlassian MCP client, a delegated Graph token for the `outlook` and `teams` CLIs).

The agent process never handles OIDC, never reads a long-lived secret, and never sees a signing key. Where the target accepts Okta tokens (AWS, ServiceNow) the daemon mints them directly. Where it does not (GitHub, Microsoft 365, Atlassian) the agent is a real user account and the daemon is a **vault and refresher** for that account's credential, kept behind the Okta-federated role where possible. The kill switch is therefore two-part: disable the agent's Okta application, and disable the agent's user account in AD/Okta (which SCIM and sync carry to GitHub and Entra). Exposure windows are in §13.

## 2. Decisions already made (inputs to this PRD)

| # | Decision | Notes |
|---|---|---|
| D1 | Okta **OIDC** is the identity root. | Agents are *workload identities* (OAuth client credentials with `private_key_jwt`), one Okta application per agent. No shared client. |
| D2 | A **daemon**, not a wrapper CLI, owns all credential logic. | One implementation of Okta/OIDC; downstream tools stay stock. |
| D3 | `aws`, `gh`, `git` stay **unmodified**. | The daemon feeds them through their native credential mechanisms. |
| D4 | Custom CLIs are limited to **`snow`**, **`outlook`** and **`teams`**. | No adequate stock CLI for ITSM/CMDB work or for agent-safe mail and Teams access. |
| D5 | Atlassian is accessed through the **Rovo MCP server**. | MCP is acceptable there; other systems use CLIs. |
| D6 | Microsoft 365 is reached **delegated, as the agent's own Entra user**, through Graph, with no relay service. | Graph cannot send Teams messages app-only. The daemon holds a delegated refresh token; humans enroll it once. See §7.5. |
| D7 | GitHub access is the agent's **EMU user account**, using a fine-grained PAT or an OAuth device-flow token chosen per agent. | Enterprise limits on GitHub Apps rule out App-per-agent. See §7.2. |

## 3. Goals and non-goals

**Goals**

- G1. No long-lived secret is ever readable by the agent's OS user.
- G2. Per-agent identity end to end (Okta app → AWS session name → GitHub EMU user → ServiceNow user → Entra user) so every action is attributable to one agent.
- G3. Credentials refresh invisibly; the agent never handles expiry.
- G4. One binary, one config file, same behavior on macOS, Linux desktops and cloud (VM/container).
- G5. Fail closed: if Okta says the agent is disabled, or the agent's user account is disabled, every credential the daemon controls is withdrawn or stops working (exposure windows in §13).
- G6. Auditable: every mint, refresh, serve and revoke is logged without logging secrets.

**Non-goals**

- Authorization decisions. The boundary is always *server side* (IAM, GitHub teams/rulesets, ServiceNow roles/ACLs, Atlassian permissions, Exchange/Teams policy). The daemon only gets credentials; it does not decide what they may do.
- Human login. Humans use `snow auth login` (PKCE) or their normal SSO; the daemon serves agents only.
- Model-provider (LLM) credentials. Out of scope, though the generic `secret` provider (§7.4) could carry them later.
- Windows hosts (v1). macOS and Linux only; see Open Questions.
- An MCP gateway/proxy. Revisit only if the harness cannot inject MCP headers (§7.4).

## 4. Deployment topologies

| Topology | Daemon runs as | Okta key custody | Assurance |
|---|---|---|---|
| **A. Cloud VM / container (AWS)** | Separate OS user or sidecar container | AWS KMS asymmetric key; host IAM role may only `kms:Sign` with that key | High |
| **B. macOS desktop** | LaunchDaemon under a dedicated service user (e.g. `_agentd`) | Keychain item owned by the service user; Secure Enclave P-256 (ES256) if Okta accepts it ⚠️ | Medium-high |
| **C. Linux desktop / on-prem VM** | systemd service under a dedicated user | TPM2-sealed key if available; otherwise a `0400` key file owned by the daemon user | Medium (file) |

**Hard requirement (all topologies):** the daemon and the agent/harness run as **different OS principals**. If they share a user, the agent (an LLM with a shell) can read the key and every other control is moot.

## 5. Architecture

```
┌──────────────────────────── agent host ─────────────────────────────┐
│ OS user: agent  (Hermes harness + LLM-driven shell)                 │
│    aws · git · gh · snow · MCP client                               │
│        │ reads token files / git-credential / unix socket           │
│ ───────┼──────────────────── trust boundary ─────────────────────── │
│ OS user: agentd  →  agent-okta-d  →  signer (KMS | Keychain | TPM) │
└────────┼────────────────────────────────────────────────────────────┘
         │ client_assertion (private_key_jwt)
         ▼
  Okta custom authorization servers  ──►  access tokens
   agents-aws   (aud sts.amazonaws.com)
   agents-snow  (aud snow-agents)
         │
         ├─► AWS: aws CLI calls STS AssumeRoleWithWebIdentity itself (token file)
         │       └─► same AWS role reads user-credential secrets (GitHub token, Graph refresh token)
         ├─► ServiceNow: Okta token sent as Bearer; ServiceNow validates it
         ├─► GitHub: agent's EMU user credential (PAT or OAuth device token) from the secret store
         ├─► Microsoft 365: delegated refresh token → Graph access token (Outlook, Teams as the agent user)
         └─► Atlassian: service-account API key fetched from Secrets Manager
```

## 6. Okta requirements

### 6.1 Authorization servers

Custom authorization servers require Okta API Access Management ✅. Org authorization server must **not** be used for downstream audiences: its audience is fixed to the org URL and cannot be customized ✅.

| AS name | Audience (`aud`) | Scope | Consumer | Access-token TTL (target) |
|---|---|---|---|---|
| `agents-aws` | `sts.amazonaws.com` | `aws.assume` | AWS IAM OIDC provider | 60 min |
| `agents-snow` | `snow-agents` | `snow.agent` | ServiceNow OIDC provider record #1 | 10 min ⚠️ (confirm Okta's minimum lifetime) |
| `humans-snow` | `snow-humans` | `snow.user` | ServiceNow OIDC provider record #2 (used by `snow`, see companion PRD) | per policy |

That is three custom authorization servers (v0.1 had five; the Entra and Teams-relay servers are no longer needed). Confirm your Okta contract's limit before committing (§15).

**Why one AS per audience.** Okta's older documentation states a custom AS supports one audience ✅; multiple audiences bound via the `resource` parameter exist but are marked **self-service Early Access** ✅. Use one AS per downstream audience for GA safety; revisit when multi-audience reaches GA.

Each agent's client must be assigned to the AS(es) it needs, and each AS needs an access-policy rule permitting the client-credentials grant for that client and the specific scope. Client-credentials requests on a custom AS must request a custom scope ⚠️ (no `openid`).

### 6.2 Per-agent Okta application

- Type: **API Services** (OAuth 2.0 service app) ✅.
- Client authentication: **Public key / Private key** (`private_key_jwt`). Switching to this method deletes any existing client secret ✅. No client secret may exist.
- Register ≥ 1 public key as JWK (with `kid`). Support two simultaneous keys for rotation.
- Naming: `agent-<agent-id>`; description holds owner, team, ticket reference.
- Directory linkage: record the AD identity / owning human in app profile or label so audit can map client → AD identity → human owner.

### 6.3 Client assertion (what the daemon builds)

POST to `https://{org}/oauth2/{asId}/v1/token` ✅ (form-encoded):

```
grant_type=client_credentials
scope=<scope>
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=<signed JWT>
```

JWT header: `alg` (RS256 or ES256 ⚠️ confirm ES256 accepted), `kid` = registered key id.
JWT claims: `iss` = client_id ✅, `sub` = client_id ✅, `aud` = the token endpoint URL of that AS ✅, `iat` = now, `exp` = now + 60 s (Okta allows up to 60 min ✅; keep short), `jti` = random unique per request.

Note: when a service app requests **Okta API scopes** from the org AS, `private_key_jwt` is the only allowed method ✅. For our custom AS, secrets would also be allowed ✅ — we forbid them by policy (G1).

### 6.4 Rate limits and errors

Handle HTTP 429 using the `X-Rate-Limit-Reset` header ✅. Expected steady load is tiny (≈ 2 tokens per agent per hour), so limits matter only during mass restarts: add start-up jitter (0–30 s).

### 6.5 Onboarding / offboarding

Manage per-agent resources as code (Okta Terraform provider ⚠️ confirm module availability): Okta app + key registration + AS assignment + policy rule, AWS IAM role + trust policy, Secrets Manager entries for the agent's user credentials, ServiceNow user + roles, Atlassian service account. The agent's GitHub EMU account and Entra user come from the normal AD group/SCIM process; their one-time credential enrollment (`enroll github`, `enroll msgraph`) is a human-assisted runbook step. `agent-okta-d enroll` generates the key pair in the configured signer and emits the public JWK plus a checklist; it does not need Okta admin rights.

Offboarding = disable Okta app → run `revoke` runbook (§13) → remove downstream identities.

### 6.6 Roadmap watch: Okta Agent SSO / Cross App Access / Okta for AI Agents

Okta's 2026 release notes show Cross App Access (ID-JAG) support for AI agents rolling out to all customers in August 2026 ✅, and Okta announced Agent SSO as generally available ✅. However, one third-party source still described Cross App Access as early access in mid-2026 ⚠️. Two separate points:

- **ID-JAG is on-behalf-of-a-user.** It needs a signed-in user as subject. Our agents are autonomous teammates, so client credentials remains the right v1 flow.
- **Okta for AI Agents** is a separate paid product that registers agents as first-class identities with named human owners and supports token exchange for vaulted secrets and service accounts ✅. This could replace our Atlassian secret path (§7.4) and add owner governance. Ask your Okta account team for GA status and licensing before committing.

Design consequence: the provider interface (§9) must allow swapping the "get Okta token" step later without touching providers.

---

## 7. Provider requirements

### 7.1 AWS

**Mechanism.** The AWS CLI/SDKs natively support `AssumeRoleWithWebIdentity` from a profile with `role_arn` and `web_identity_token_file`; the tool reads the file and passes it as the web identity token ✅. Equivalent environment variables: `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_SESSION_NAME` ✅. The daemon's only job is to keep that file holding a valid token.

| ID | Requirement | Pri |
|---|---|---|
| AWS-1 | Mint an `agents-aws` access token and write it to `token_file` **atomically** (temp file + `rename`), mode `0440`, owner `agentd`, group `agent`. | P0 |
| AWS-2 | Refresh at ≤ 50 % of token TTL so the file is valid whenever the CLI re-calls STS (it re-reads the file at refresh time). | P0 |
| AWS-3 | `agent-okta-d configure aws` writes (or prints) the profile/env snippet below, with `role_session_name` = agent id so CloudTrail attributes actions. | P0 |
| AWS-4 | `doctor` verifies the path end to end with `sts:GetCallerIdentity` using the file. | P0 |
| AWS-5 | On revoke/shutdown, delete the token file. | P0 |
| AWS-6 | Optional: custom claim `https://aws.amazon.com/tags` for session tags ⚠️. | P2 |

Profile:

```ini
[profile agent]
role_arn = arn:aws:iam::222222222222:role/agent-sdlc-reviewer-01
web_identity_token_file = /run/agentd/sdlc-reviewer-01/aws-web-identity.jwt
role_session_name = sdlc-reviewer-01
region = us-east-1
```

**AWS-side prerequisites**

- IAM OIDC provider with URL `https://{org}/oauth2/{agents-aws-id}`. A thumbprint is no longer needed for validation of IdPs whose certificates chain to AWS's trusted CA library ✅ (the API parameter is optional ✅).
- One role per agent (or per agent function), with a trust policy that **always** pins both `aud` and `sub`. Unpinned `sub` is the classic OIDC federation mistake ✅.

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::222222222222:oidc-provider/EXAMPLE.okta.com/oauth2/AS_ID" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": { "StringEquals": {
    "EXAMPLE.okta.com/oauth2/AS_ID:aud": "sts.amazonaws.com",
    "EXAMPLE.okta.com/oauth2/AS_ID:sub": "<agent Okta client_id>"
  } }
}
```

For a service app's client-credentials token, `sub` is the client ID ✅ (Okta sets `sub` = `client_id` in the assertion; the access token's `sub` for this flow should be verified ⚠️ against a real token before pinning).

- Permissions policy least-privilege + permissions boundary + SCP guardrails. The agent role is the boundary, not the CLI.
- **Known tool quirk:** AWS CDK CLI has had an issue with profile-based web-identity configs while the AWS CLI worked ✅ (aws-cdk issue 25870). Test CDK/Terraform/boto3 explicitly; prefer the env-var form if a tool misbehaves with profiles.

### 7.2 GitHub (Enterprise Managed User per agent)

**Mechanism.** Each agent is an **Enterprise Managed User (EMU)** provisioned from the IdP (the agents are already in the right AD group). GitHub validates only its own credentials on the API, so Okta cannot mint a GitHub token. Okta's role is (a) the one-time SSO sign-in that proves the agent identity when a credential is created, and (b) SCIM provisioning/deprovisioning: removing the agent from the AD/Okta group suspends the EMU account and with it every credential it owns. Two credential modes are supported and selected **per agent** (`providers.github.mode`), because team structure and enterprise policy differ:

| | Mode `pat`: fine-grained PAT | Mode `oauth_device`: OAuth app token (device flow) |
|---|---|---|
| What it is | Fine-grained personal access token owned by the EMU user | OAuth access token for the EMU user from the OAuth 2.0 device flow (the same mechanism `gh auth login --web` uses) |
| Created by | Operator, once, in the GitHub web UI while signed in via Okta SSO ⚠️ (no documented API for creating user PATs) | Operator, once, approving a device code in a browser signed in as the agent user |
| Lifetime | Enterprise-capped; default maximum 366 days for fine-grained tokens ✅ | Long-lived, manual revocation; revoked automatically after one year unused ✅ |
| Scope control | Per-repository and per-permission, chosen at creation ✅ | OAuth scopes (`repo`, `read:org`, `workflow`, ...), coarser than fine-grained ✅ |
| Governance | Enterprise can restrict PATs, set max lifetime and require owner approval for fine-grained tokens ✅; classic PATs are not subject to approval ✅ | Depends on the enterprise/org OAuth-app access policy ⚠️ (confirm the OAuth app you use is allowed for EMU users) |
| Rotation | Human or browser step before expiry; daemon alarms at 30 days | Normally none |
| Best when | Narrow repo set, auditors want an expiring, approved, scoped token | Many repos, broad team access, or PAT approval is impractical |

The two earlier ideas (GitHub App per agent; one App with user-to-server tokens) are **dropped**: the enterprise limits Apps, and a per-agent App cannot scale to the agent population.

| ID | Requirement | Pri |
|---|---|---|
| GH-1 | `github` provider with `mode: pat \| oauth_device`. Credential kind `static-secret`: the daemon holds it, never mints it. | P0 |
| GH-2 | Fetch the credential from the configured **secret store** (§7.4 `secret` machinery: AWS Secrets Manager through the agent's Okta-federated AWS role, or OS keychain). Hold in memory only; re-fetch on interval/rotation. | P0 |
| GH-3 | `credential-helper github`: git `get` returns username = the agent's EMU login and password = the token (any non-empty username works for PATs ✅); `store`/`erase` are no-ops so `git` can never overwrite it. | P0 |
| GH-4 | `token github --format raw` for `GH_TOKEN`. Ship the `gh` shim: export `GH_TOKEN` per invocation, then `exec` the real `gh`. `gh auth login` stays unused so no token is stored in `gh`'s own config. | P0 |
| GH-5 | `enroll github --mode oauth_device`: run the device flow (RFC 8628) against the configured `oauth_client_id` (default: the GitHub CLI's public OAuth app ⚠️ if the enterprise allows it), print the user code and URL, poll, then write the token to the secret store. `enroll github --mode pat` reads the PAT from stdin/prompt and stores it. | P0 |
| GH-6 | Expiry awareness: for PATs, record `expires_at` at enrollment (or read the `github-authentication-token-expiration` response header ⚠️); `status`/`doctor` warn at ≤ 30 days and go `degraded` at expiry. | P0 |
| GH-7 | `doctor` calls `GET /user` and checks `login` equals `github.login` (guards against a wrong token stored for the wrong agent), then a read on one allowed repo. | P0 |
| GH-8 | `configure git` sets `user.name` and `user.email` for the EMU user (noreply form `<id>+<login>@users.noreply.github.com` ⚠️ confirm for your EMU/GHE.com setup; id from `GET /user`). | P0 |
| GH-9 | On 401 re-fetch the secret once, then enter `reauth_required` (§8 FR-17), not `revoked`. On 403/429 surface `Retry-After`, never hammer. | P0 |
| GH-10 | Configurable API base URL (github.com, GHES `/api/v3`, GHEC data residency `*.ghe.com`). | P1 |
| GH-11 | Rotation: secret store keeps a `next` version; daemon swaps without restart. | P1 |
| GH-12 | Optional SSH commit-signing key held by the daemon user and exposed through a restricted `ssh-agent` socket, if the org requires signed commits ⚠️. | P2 |

Git config (system level, run by `configure git`):

```
[credential "https://github.com"]
    helper =
    helper = !agent-okta-d credential-helper github
```

**Custody and the kill switch.** The token is a bearer secret equal to the agent's GitHub identity, so store it **behind the Okta-federated AWS role** (Secrets Manager) in cloud topologies: disabling the Okta app then stops the daemon from reading it, and disabling the AD/Okta group membership suspends the EMU account via SCIM, which kills the token itself. On desktops without AWS, the OS keychain readable only by the daemon user is the fallback (and weaker, §15).

**GitHub-side prerequisites / policy items**

- Provision each agent as an EMU user via SCIM into the agreed group; give it a recognizable naming convention (e.g. `agent-<id>_<shortcode>`) so humans and automation can tell agents apart. Each agent consumes a GitHub license seat ⚠️ (confirm cost model).
- Repository access through **teams** and **rulesets**, not per-user grants, so offboarding is group removal.
- **Self-approval and separation of duties.** An agent user can approve PRs like any human. Use rulesets (required reviewers from a human team, "dismiss stale approvals", author cannot approve own PR ✅ GitHub already blocks self-approval) and CODEOWNERS that name human teams. Decide whether an agent approval may count toward required reviews.
- PAT mode: set the enterprise PAT policy deliberately (allow fine-grained, set max lifetime, require approval or not, decide on classic PATs ✅).
- OAuth mode: confirm the OAuth app is permitted for EMU users and that SSO authorization works for the token ⚠️.
- Signed commits: if required, plan GH-12 or API-created commits ⚠️.

### 7.3 ServiceNow

**Mechanism.** ServiceNow can accept an ID or access token issued by a third-party OIDC provider such as Okta ("Third-party ID token" flow) ✅. It validates the token signature with the provider's keys and maps a claim to a `sys_user` record; roles then come from that user ✅. No ServiceNow-issued token is involved, so the daemon only needs to supply an Okta token with the right audience.

| ID | Requirement | Pri |
|---|---|---|
| SN-1 | Mint an `agents-snow` access token with `aud` = `snow-agents`, scope `snow.agent`. | P0 |
| SN-2 | Serve via `agent-okta-d token servicenow` and the unix-socket API (`snow` uses the Go client library). Never write this token to disk by default. | P0 |
| SN-3 | Enforce `min_ttl_seconds` (default 120): if less remains, refresh synchronously before answering. | P0 |
| SN-4 | `doctor` calls the `snow whoami` endpoint (see companion PRD) with the token. | P0 |
| SN-5 | Fallback provider `servicenow-jwt-bearer` (P2): sign a JWT with the agent key and exchange at ServiceNow's OAuth token endpoint using the JWT-bearer grant. ServiceNow's JWT grant returns no refresh token ✅ and needs the public key in `sys_certificate` ✅. Use only if the third-party-token flow is unavailable on your release. | P2 |

**ServiceNow-side prerequisites** (details and role matrix in `snow-cli-PRD.md`)

- OIDC provider record (Machine Identity Console → Inbound integrations → *Third party ID token*, or `oidc_provider_configuration`) ✅ with OIDC metadata URL of `agents-snow`, **Client ID equal to the token's `aud`** ✅, and a User Claim → User Field mapping ✅. Client IDs must be unique per provider record ✅, which is why agents and humans need separate audiences.
- **User mapping gotcha.** Client-credentials tokens carry the client ID as `sub` and no email. Either map `sub` to a field on the agent's `sys_user` (e.g. `user_name` = Okta client ID), or add a custom claim in `agents-snow` that carries the agent id ⚠️ (confirm Okta Expression Language can read app attributes in this flow).
- **JTI replay check.** ServiceNow can verify the `jti` claim; ServiceNow's own MCP documentation recommends leaving it off when a client reuses one token across calls, because enabling it forces a fresh token per request ✅. Recommendation: leave off, keep `agents-snow` TTL short (10 min), and deactivate the `sys_user` for immediate cut-off.

### 7.4 Atlassian

**Mechanism.** Atlassian does not accept Okta tokens for this path. The Rovo MCP server supports OAuth 2.1 (interactive) and, if an Atlassian org admin enables it, **API-token auth for non-interactive clients**: a service-account API key sent as `Authorization: Bearer` ✅ (endpoint `https://mcp.atlassian.com/v2/mcp` ✅). Admin enablement is under Atlassian Administration → Rovo → Rovo MCP server → Authentication ✅. Caveats: some tools are unavailable with API-key scopes ✅; Jira Service Management and Bitbucket Cloud tools work only with API-token auth, Compass only with OAuth ✅.

So for Atlassian the daemon is a **secret broker**, not a token minter.

| ID | Requirement | Pri |
|---|---|---|
| AT-1 | Generic `secret` provider type: fetch a secret from AWS Secrets Manager using the agent's Okta-federated AWS role; hold in memory; re-fetch on a configured interval or on rotation event. | P0 |
| AT-2 | Deliver to the MCP client by one of: (a) render a `0440` file containing the header value or full MCP config that the harness reads; (b) serve over the unix socket; (c) P2: tiny local header-injecting MCP proxy if Hermes cannot re-read headers without restart. | P0 (a), P2 (c) |
| AT-3 | Never write the key into the harness's world-readable config; permissions as AWS-1. | P0 |
| AT-4 | Rotation: support a "next" secret version and zero-downtime swap. | P1 |

**Concerns.** A service-account API key is a shared bearer secret, so (i) it is **not** tied to the Okta kill switch unless vaulted behind Okta, and (ii) audit shows the service account, not a person. Mitigations: one Atlassian service account per agent; short key expiry where Atlassian allows; admin-side IP allowlisting ✅ (applies to MCP); evaluate Okta's vaulted-secret token exchange (§6.6).
Open: Hermes MCP client's ability to take dynamic headers (§16).

### 7.5 Microsoft 365: Outlook and Teams as the agent's own user (delegated Graph)

**Mechanism.** The agent is a normal Entra user (synced from AD) with a mailbox and a Teams license. The `outlook` and `teams` CLIs call Microsoft Graph **delegated as that user**. This needs no relay and no per-agent app registration. Why delegated:

- Graph's app-only path cannot send Teams chat or channel messages; the only application permission for chat send is `Teamwork.Migrate.All`, for import ✅. Delegated `ChatMessage.Send` / `Chat.ReadWrite` do send ✅.
- ROPC (username and password) is not usable: it fails with MFA, does not work for federated users except in special cases, and Microsoft recommends against it ✅.
- Entra federated identity credentials (the Okta→Entra exchange used in v0.1) apply to apps and managed identities, not to user sign-in ⚠️. Okta can therefore not directly mint a user token for Graph.

So the daemon holds a **delegated refresh token** for the agent user and mints short-lived Graph access tokens from it.

**Enrollment (one-time, human-assisted).** `agent-okta-d enroll msgraph` runs the device-code flow against the shared public-client app: it prints a code and URL, an operator signs in **as the agent user** (satisfying Okta/Entra sign-in and MFA once), and the daemon stores the resulting refresh token (requested with `offline_access`) in the token store.

| ID | Requirement | Pri |
|---|---|---|
| MG-1 | Provider `msgraph`, credential kind `bearer` (Graph access token). Mint with `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`, `grant_type=refresh_token`, `client_id` = shared app, `scope` = configured delegated scopes ⚠️ (standard refresh flow; verify in your tenant). | P0 |
| MG-2 | Persist any **new refresh token** returned by the token endpoint to the token store before using the access token; never log either. | P0 |
| MG-3 | Token store abstraction: `aws-secretsmanager` (read via the agent's Okta-federated role; write requires `secretsmanager:PutSecretValue` on that one secret), `keychain`, or `file-encrypted` (key in the configured signer). | P0 |
| MG-4 | Cache the access token, refresh at 50 % of lifetime, serve over the socket as provider `msgraph`. No file sink. One token serves both CLIs (same resource, Graph). | P0 |
| MG-5 | Error mapping: `invalid_grant` variants (user disabled, password reset, refresh token expired or revoked by Conditional Access/CAE, sign-in frequency exceeded) → state `reauth_required` and exit-code semantics of FR-17, never auto-retried. Network/5xx → transient. | P0 |
| MG-6 | `doctor`: `GET /me` returns the expected UPN; `GET /me/mailFolders/inbox` succeeds; `GET /me/chats?$top=1` succeeds; **negative test**: `GET /users/{other}/messages` returns 403. | P0 |
| MG-7 | `status` shows refresh-token age and, if the tenant policy is known, a configured `reauth_warning_days`. | P1 |
| MG-8 | `enroll msgraph --auth-code` (loopback PKCE) as an alternative when device code is blocked by policy. | P2 |

**Delegated scopes (request only what the agent's role needs).**

| Capability | Scope | Admin consent | Notes |
|---|---|---|---|
| Identity | `User.Read`, `offline_access` | no | `offline_access` is required to get a refresh token ✅ |
| Mail read/write | `Mail.ReadWrite` | no | Own mailbox only; do **not** request the `.Shared` variants |
| Mail send | `Mail.Send` | no | |
| Teams chats | `Chat.ReadWrite` (or least-privileged `ChatMessage.Send` for send-only) ✅ | no | |
| Teams channels | `ChannelMessage.Send`, `ChannelMessage.Read.All`, `Channel.ReadBasic.All` | **yes** | Read.All is limited to channels the agent user can see |
| Calendar (P2) | `Calendars.ReadWrite` | no | |

**Server-side prerequisites**

- One **shared** Entra app registration (`agent-graph-cli`), public client flows enabled, **User assignment required**, assigned only to the agent group; admin consent for the scopes above. One app serves all agents, so the 20-credentials-per-app limit no longer applies.
- Agent user: licensed for Exchange Online and Teams; mailbox created; Teams chat reachable.
- **Conditional Access for the agent group:** decide explicitly what applies to non-interactive refresh-token use: sign-in frequency, MFA/compliant-device requirements (these will break unattended use if applied naively), named-location restriction to agent host egress IPs, and Continuous Access Evaluation ⚠️. Document the tested behavior; it determines how often a human must re-enroll.
- Disabling the user in AD/Entra (or revoking sessions with `Revoke-MgUserSignInSession`) is the kill switch ⚠️; measure propagation (§13).
- Mail-flow rules (recipient allow-list, DLP, external tagging) on the agent mailbox remain the control on *where* mail can go; they are independent of the auth model.

**What is lost compared with v0.1.** Exchange RBAC for Applications no longer scopes the mailbox, but the delegated token reaches only the agent's own mailbox plus whatever else the agent user has been granted (so grant nothing: no shared-mailbox delegation, no site membership beyond need). The Okta kill switch no longer directly covers Microsoft; it is covered by account disablement and, in cloud topologies, by keeping the refresh token in Secrets Manager behind the Okta-federated role.

### 7.6 Teams-specific notes

- **Send:** `POST /chats/{id}/messages` and `POST /teams/{id}/channels/{id}/messages` as the agent user ✅ (delegated).
- **Receive without a relay:** change notifications need a public HTTPS endpoint, which is exactly what we are not hosting. The `teams` CLI therefore **polls** (`GET /me/chats/{id}/messages` with `$filter` on `lastModifiedDateTime`, or the chats message delta endpoint ⚠️) at a configurable interval and tracks a per-chat cursor locally. Message latency equals the polling interval; Graph throttling must be respected (`Retry-After`).
- **Identity in chats:** messages come from the agent's own account (display name, presence, directory entry). Humans can chat with it like a teammate; no bot app package, no Teams app approval.
- **Licensing/policy:** the agent user needs a Teams license; tenant Teams policies for external access and messaging apply as for any user.

### 7.7 Roadmap: Entra Agent ID "agent user"

Microsoft's agent identity model (Agent Identity Blueprint → Agent Identity → optional **Agent User**) gives an agent its own user object with a mailbox, Teams presence and directory listing ✅, and avoids a human-assisted refresh-token enrollment: the token chain is blueprint credential → agent identity token → agent-user token via `user_fic` ✅, and a federated credential can sit on the blueprint ✅ (so Okta could be the trust root again). Caveats: Agent 365 is described as generally available from 2026-05-01 ✅, but creating an Agent User uses Microsoft Graph **beta**, needs a Microsoft 365 license per agent user, and user-account mode is described as requiring the Frontier preview program ✅; Microsoft's reference implementation is explicitly research-grade ✅. Keep as a P2 alternative implementation of the `msgraph` provider (`provider: entra-agent-user`) so the CLIs do not change; spike it in M0 to compare re-enrollment burden and kill-switch behavior.

---

## 8. Core daemon requirements

| ID | Requirement | Pri |
|---|---|---|
| FR-1 | Single static binary; subcommands in §11; one YAML config (§10). | P0 |
| FR-2 | Build and sign Okta client assertions via a `Signer` abstraction (KMS, Keychain, TPM, file for dev only). When the signer is KMS ES256, convert KMS's DER ECDSA output to JOSE raw `R‖S` ⚠️. | P0 |
| FR-3 | Token cache keyed by (provider, audience, scope); in-memory only; **single-flight** refresh. | P0 |
| FR-4 | Proactive refresh at `fraction` (default 0.5) of TTL ± jitter, never later than `min_margin_seconds` before expiry. | P0 |
| FR-5 | Transient errors (network, 5xx, 429): exponential backoff 1 s → 60 s with jitter until expiry − 30 s; then state = `degraded`, API returns 503 + `Retry-After`. | P0 |
| FR-6 | Definitive auth errors from Okta (`invalid_client`, `unauthorized_client`, `invalid_grant`, `access_denied`, client inactive) confirmed twice within 30 s → state = `revoked` (§13). Never treat 5xx as revocation. | P0 |
| FR-7 | Local API over a **unix domain socket**; authenticate callers by peer credentials (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED`/`LOCAL_PEERPID` on macOS); allow-list by gid per provider. | P0 |
| FR-8 | Atomic file sinks (temp + fsync + rename), configured mode/owner, removed on stop/revoke; wipe stale sinks at start. | P0 |
| FR-9 | Startup self-test (`doctor` logic): Okta reachable, key usable, assertion accepted, clock skew < 30 s (query Okta `Date` header), each enabled provider dry-run. Refuse to serve a provider whose test fails. | P0 |
| FR-10 | Structured JSON logs; **a redaction layer** guarantees no token, assertion, or key material is logged, including on error paths and in panics. | P0 |
| FR-11 | Audit events (§12) for mint, refresh, serve (caller uid/pid/exe best-effort), failure, state change, revoke. | P0 |
| FR-12 | Metrics (Prometheus/OTel): refresh count/errors per provider, seconds-to-expiry gauge, state gauge, serve count by caller. | P1 |
| FR-13 | Hot-reload config on SIGHUP for non-key changes; key rotation via two registered `kid`s with an overlap window. | P1 |
| FR-14 | Memory hygiene: zero secret buffers where the language allows; disable core dumps; `mlock` best effort. | P1 |
| FR-15 | Supervisor integration: exit code 78 (config) and 77 (revoked) tell systemd/launchd *not* to restart-loop. | P0 |
| FR-16 | `revoke` subcommand and signal handler implement the full withdraw sequence (§13). | P0 |
| FR-17 | State `reauth_required` for user-account providers (`github`, `msgraph`) when the stored credential is expired, rejected or consented away. It is distinct from `revoked`: the daemon keeps serving other providers, returns 401-style `reauth_required` for that provider, emits an alert, and waits for `enroll <provider>`. Never retry-loop. | P0 |
| FR-18 | **User-credential custody** (`github`, `msgraph`, Atlassian): secret store abstraction (`aws-secretsmanager` via the Okta-federated role, `keychain`, `file-encrypted`); secrets are read into memory only; writes (refresh-token rotation) are atomic and versioned. | P0 |

## 9. Code-level requirements

**Language/stack recommendation: Go.** Static binaries, easy macOS/Linux cross-compilation, mature JWT/JOSE and AWS SDK v2 libraries, strong concurrency primitives for single-flight and schedulers. Alternatives (Rust, Python) are workable, but Python is a poor fit for a binary that must resist an adversarial local user and be signed/notarized.

**Module layout**

```
cmd/agent-okta-d/        subcommands, signal handling, exit codes
internal/config/         YAML load, validation, defaults
internal/signer/         Signer interface; kms/, keychain/, tpm/, file/
internal/okta/           client_assertion builder, token client, clock-skew check
internal/provider/       Provider interface; aws/, github/, servicenow/, msgraph/, secret/
internal/store/          secret stores: awssm/, keychain/, encfile/
internal/enroll/         device-flow and PAT enrollment helpers
internal/cache/          entry state machine, single-flight, scheduler
internal/ipc/            unix-socket server, peercred, handlers
internal/sink/           atomic file writer
internal/obs/            logging+redaction, audit, metrics
pkg/client/              Go client library (consumed by agent-cli-core's `auth` package; the snow, outlook, teams CLIs get it through the core)
```

**Core interfaces**

```go
type Signer interface {
    Sign(ctx context.Context, alg string, signingInput []byte) (sig []byte, kid string, err error)
    Public() (jwk []byte, err error)       // for `enroll`
}

type Provider interface {
    Name() string
    Mint(ctx context.Context, d Deps) (Credential, error)   // may use Okta, other providers' creds
    Sinks() []SinkSpec
    Revoke(ctx context.Context, c Credential) error          // best effort
    Probe(ctx context.Context, c Credential) error           // used by doctor
}

type Credential struct {
    Kind      string            // "bearer", "aws-web-identity", "static-secret"
    Value     SecretString      // redacting type; String() returns "[redacted]"
    IssuedAt  time.Time
    ExpiresAt time.Time
    Meta      map[string]string // audience, scope, kid (never secrets)
}
```

`Deps` gives a provider access to the Okta token source and to other providers' credentials. This is how the `github`, `msgraph` and `secret` providers obtain the AWS session needed to read their secrets.

**Cache entry states:** `empty → minting → valid → refreshing → valid`, with `degraded` and `revoked` terminal-ish states. Transitions are logged and exported as a metric.

**Error taxonomy:** `ErrTransient`, `ErrAuthDefinitive`, `ErrConfig`, `ErrPolicy`, `ErrProvider(provider, cause)`. Only `ErrAuthDefinitive` can trigger `revoked`.

**Testing requirements**

- Unit: assertion construction (claims, expiry, `jti` uniqueness), scheduler timing with fake clock, redaction (fuzz that no secret appears in any log line), DER→JOSE conversion.
- Contract: mock Okta token endpoint including 429, 5xx, `invalid_client`.
- Integration (sandbox Okta/AWS/GitHub/ServiceNow): full path per provider; CDK/Terraform/boto3 smoke test for AWS.
- Security: agent user cannot read key or sockets of other agents; `strings`/memory scan finds no private key in daemon heap dumps where feasible; token never appears in `ps`, env of child processes, or logs.
- Failure drills: network partition, clock skew ±5 min, Okta app disabled mid-run, daemon SIGKILL (sinks left behind → wiped at next start).

## 10. Configuration reference

```yaml
agent:
  id: sdlc-reviewer-01              # stable id; AWS session name, bot identity, log field
  environment: prod

okta:
  org_url: https://EXAMPLE.okta.com
  client_id: 0oa...                 # per-agent API Services app
  signer:
    type: kms                       # kms | keychain | tpm | file (dev only)
    key_id: arn:aws:kms:us-east-1:111111111111:key/...
    alg: RS256                      # RS256 | ES256
    kid: sdlc-reviewer-01-2026q4

providers:
  aws:
    authorization_server: agents-aws
    scope: aws.assume
    token_file: /run/agentd/sdlc-reviewer-01/aws-web-identity.jwt
    file_mode: "0440"
    role_arn: arn:aws:iam::222222222222:role/agent-sdlc-reviewer-01
    role_session_name: sdlc-reviewer-01
    region: us-east-1

  github:
    api_base: https://api.github.com
    mode: pat                       # pat | oauth_device  (per agent)
    login: agent-sdlc-reviewer-01_acme   # EMU login; doctor checks GET /user matches
    oauth_client_id: ""             # oauth_device only (default: GitHub CLI public app, if allowed)
    store:                          # where the credential lives
      type: aws-secretsmanager      # aws-secretsmanager | keychain | file-encrypted
      secret_id: arn:aws:secretsmanager:us-east-1:222222222222:secret:agents/sdlc-reviewer-01/github
    expiry_warning_days: 30
    git_identity:
      name: "sdlc-reviewer-01"
      email: "<id>+<login>@users.noreply.github.com"

  servicenow:
    instance_url: https://EXAMPLE.service-now.com
    authorization_server: agents-snow
    scope: snow.agent
    min_ttl_seconds: 120

  msgraph:
    tenant_id: 00000000-0000-0000-0000-000000000000
    app_client_id: 11111111-1111-1111-1111-111111111111   # ONE shared public-client app for all agents
    upn: sdlc-reviewer-01@example.com                      # doctor checks GET /me matches
    scopes: [User.Read, offline_access, Mail.ReadWrite, Mail.Send, Chat.ReadWrite, ChannelMessage.Send]
    store:
      type: aws-secretsmanager      # refresh token; daemon role needs Get+Put on this secret only
      secret_id: arn:aws:secretsmanager:us-east-1:222222222222:secret:agents/sdlc-reviewer-01/msgraph
    reauth_warning_days: 14

  atlassian:
    type: secret
    source: aws-secretsmanager
    secret_id: arn:aws:secretsmanager:us-east-1:222222222222:secret:agents/sdlc-reviewer-01/atlassian
    sink: { file: /run/agentd/sdlc-reviewer-01/atlassian.key, mode: "0440" }

refresh: { fraction: 0.5, jitter: 0.05, min_margin_seconds: 120 }
ipc:     { socket: /run/agentd/sdlc-reviewer-01/agentd.sock, allow_gids: [agent] }
log:     { level: info, format: json, destination: stderr }
```

macOS uses `/var/run/agentd/` (LaunchDaemon creates it); paths are configurable.

## 11. Local API and CLI

**Unix-socket HTTP API** (JSON; peer-credential authenticated)

| Endpoint | Purpose |
|---|---|
| `GET /v1/credentials/{provider}` | Returns `{token_type, access_token, issued_at, expires_at, audience}`; refreshes synchronously if `< min_ttl` |
| `POST /v1/credentials/{provider}/refresh` | Force refresh |
| `GET /v1/status` | Per-provider state, expiry, last error (no secrets) |
| `GET /v1/identity` | Agent id, Okta client id, `kid`, versions |
| `GET /healthz` | Liveness for supervisors |

**CLI** (`agent-okta-d <cmd>`)

| Command | Purpose |
|---|---|
| `run` | Start the daemon |
| `token <provider> [--format raw\|json]` | Print current credential (talks to the socket) |
| `credential-helper <provider> get\|store\|erase` | git credential protocol |
| `env <provider>` | Emit `export` lines (e.g. `GH_TOKEN`) for shims/hooks |
| `status`, `doctor` | Health and end-to-end self-test |
| `enroll [okta]` | Generate key in the configured signer; print public JWK + onboarding checklist |
| `enroll github --mode pat\|oauth_device` | Store the agent's GitHub credential (device flow or pasted PAT) in the secret store |
| `enroll msgraph` | Device-code sign-in as the agent user; store the refresh token |
| `configure aws\|git\|gh` | Write/print native tool configuration |
| `revoke` | Execute the withdraw sequence now |

## 12. Non-functional requirements

- **Security:** daemon runs unprivileged except for socket/dir setup; no network listeners (unix socket only); config file `0640` daemon-owned; refuse to start with world-readable key files; supply chain: reproducible builds, signed releases (cosign / Apple notarization), SBOM.
- **Availability:** a running agent must survive a 30-minute Okta outage given 60-minute AWS tokens; ServiceNow (10-minute tokens) degrades first, which is acceptable.
- **Performance:** `token` over the socket < 10 ms when cached; cold refresh < 2 s p95.
- **Portability:** macOS 14+ (arm64/x86_64), Linux (glibc/musl), container image for sidecar use.
- **Audit fields:** `ts, agent_id, event, provider, audience, jti, expires_at, caller_uid, caller_pid, caller_exe, result, error_class`. Ship to your SIEM; correlate with Okta System Log by `client_id` and `jti`.
- **Retention:** per enterprise logging policy; none of these logs contain secrets by design (FR-10).

## 13. Revocation, kill switch and exposure windows

Disabling the Okta app stops **new** tokens. Credentials already issued live until their own expiry unless actively revoked:

| System | What the agent holds | Lives until (worst case) | Faster cut-off |
|---|---|---|---|
| Okta token | Access token | AS policy TTL (10–60 min) | Okta token revocation endpoint ⚠️ |
| AWS | STS session | Session duration (default 1 h; role max up to 12 h) | IAM "revoke active sessions" (deny on `aws:TokenIssueTime`), detach policies |
| GitHub | PAT or OAuth token (bearer, not time-boxed to minutes) | Until revoked, expired or the EMU account is suspended | Remove the agent from the AD/Okta group (SCIM suspends the EMU user ✅ concept; measure delay ⚠️); enterprise "delete all user tokens" for EMU ✅; revoke the PAT/OAuth grant; with Secrets Manager custody the daemon also stops reading it when the Okta app is disabled |
| ServiceNow | Okta token validated by signature, no live check ✅ | Okta token TTL | **Deactivate the `sys_user`** (immediate) |
| Atlassian | Service-account API key | Until key revoked/expired (not tied to Okta unless vaulted) | Revoke key in Atlassian admin |
| Microsoft Graph (Outlook, Teams) | Graph access token plus a delegated refresh token | Access token ≈ 1 h ⚠️; refresh token until revoked/expired ⚠️ | Disable the Entra user and revoke sign-in sessions; Continuous Access Evaluation may shorten the window ⚠️; with Secrets Manager custody the daemon also stops refreshing when the Okta app is disabled |

**`revoke` sequence (automatic on `revoked` state, or manual):** (1) stop serving, return 403 to all callers; (2) delete all sinks; (3) call provider `Revoke` hooks (Okta token revoke; none exist for user-credential providers, whose revocation is account-side); (4) zero in-memory secrets; (5) emit a critical audit event; (6) exit 77.

**Runbook (document with the PRD):** disable Okta app → disable the agent's AD/Okta user (flows to GitHub EMU and Entra) → deactivate ServiceNow user → revoke AWS sessions → revoke GitHub token and Entra sessions → revoke Atlassian key → confirm in Okta System Log/CloudTrail/GitHub audit/ServiceNow logs. Measure the real elapsed time in a drill and publish it to risk/audit.

## 14. Delivery plan and acceptance criteria

| Milestone | Scope | Acceptance |
|---|---|---|
| **M0 Spikes (1–2 wks)** | Okta org with custom AS; one test API Services app; AWS IAM OIDC provider; EMU test user with PAT and OAuth device flow; Entra test user with device-code enrollment and Conditional Access behavior; Agent User spike; ServiceNow sandbox OIDC record; confirm every ⚠️ in this doc | Written spike report; list of confirmed/changed assumptions |
| **M1 Core + AWS** | Config, Okta assertion, cache/scheduler, socket API, file sink, logging/redaction, AWS provider, `doctor` | From the `agent` OS user with no secrets: `aws sts get-caller-identity` returns the agent role session; token file rotates for 24 h without error |
| **M2 GitHub** | `github` provider (PAT and OAuth device modes), secret store, `enroll github`, credential helper, `gh` shim, `configure git` | `git clone/push` and `gh pr create` work as the agent's EMU user in both modes; commits show the agent identity; expired PAT produces `reauth_required` and an alert, not a retry loop |
| **M3 ServiceNow** | SN provider + Go client lib; integration with `snow` | `snow whoami` and an allowed read succeed as the agent `sys_user`; disabling the `sys_user` blocks the next call |
| **M4 Atlassian** | `secret` provider; sink or proxy | Rovo MCP tools callable headless from the harness; key rotation without restart |
| **M4b Microsoft 365** | `msgraph` provider, `enroll msgraph`, token store, integration with `outlook` and `teams` CLIs | Agent reads and sends mail from its own mailbox only (cross-mailbox returns 403); posts a Teams chat message and receives a human reply by polling; refresh token survives 7 days of unattended runs; disabling the Entra user stops access within the measured window |
| **M5 Hardening** | KMS/Keychain/TPM signers, kill-switch drill, packaging/signing, metrics | Drill report with measured exposure windows; security review sign-off |
| **M6 Okta roadmap** | Evaluate Agent SSO / Okta for AI Agents | Go/no-go memo |

## 15. Concerns and recommendations

1. **GitHub identity is not Okta identity, and the credential is a bearer secret.** A PAT or OAuth token is the agent's whole GitHub identity for as long as it lives. *Recommendation:* keep it in Secrets Manager behind the Okta-federated role, scope PATs per repository with the shortest lifetime the enterprise allows, rely on SCIM deprovisioning as the real kill switch, and measure its delay. Prefer PAT mode for narrow, auditable access and OAuth mode only where PAT approval or breadth makes PATs impractical (§7.2).
2. **The kill switch is not instantaneous.** See §13. *Recommendation:* publish the exposure-window table to risk; keep Okta and ServiceNow TTLs short; prepare a scripted revoke.
3. **Same-OS-user collapse.** If the daemon and agent share a user, nothing here is real security. *Recommendation:* enforce separation in the installer and fail `doctor` if violated.
4. **Desktop key custody is weaker than cloud.** Keychain/TPM/file keys on a laptop are exposed to anyone with admin or physical access. *Recommendation:* prefer cloud-hosted agents for anything touching production; treat desktop agents as non-prod credentials with narrower IAM and ServiceNow roles.
5. **Atlassian is the weak link** (shared bearer key, not Okta-bound, partial tool coverage). *Recommendation:* one service account per agent, shortest key lifetime available, IP allowlist, and evaluate Okta vaulted secrets.
6. **ServiceNow user mapping.** Agent and human tokens need different OIDC provider records and audiences (§7.3). Decide the agent claim→field mapping early; it shapes the `sys_user` data model.
7. **Okta licensing and limits.** Custom AS needs API Access Management; confirm AS count limits and whether multi-audience (EA) is available to you.
8. **Reuse check.** Okta publishes `okta-aws-cli` with an `m2m` mode that signs a request with a private key registered on an API Services app and exchanges it for AWS credentials ✅. It can serve as a reference implementation or interim AWS path, but it covers only AWS; keep the single-daemon design.
9. **Offline/sleep behavior on desktops.** Laptops that sleep can resume with expired sinks. The daemon must refresh immediately on wake and callers must handle `503 Retry-After`.
10. **Harness integration unknowns.** Hermes' process environment, shell, and MCP-header behavior decide whether the `gh` shim, env injection, and Atlassian delivery work as written. Confirm in M0.
11. **Regulatory fit.** Agent-initiated writes to ServiceNow and GitHub intersect with change management and separation-of-duties controls. Involve risk/audit before enabling write scopes.
12. **Teams as a user means polling and a human-assisted enrollment.** No relay means no change notifications, so inbound latency equals the polling interval; and a delegated refresh token must be created by someone signing in as the agent. *Recommendation:* accept polling (30–60 s), document the enrollment ceremony and who holds the agent user's sign-in factors, and spike Entra Agent User to remove the human step later (§7.7).
13. **Email is the highest-risk agent channel**: inbound mail is untrusted instructions, outbound mail is an exfiltration path, and the agent now holds a delegated user token. *Recommendation:* grant no shared-mailbox or site access to the agent user, use mail-flow rules for recipient control, and put a policy layer in the `outlook` CLI (`outlook-cli-PRD.md`).
14. **Conditional Access is the make-or-break item for unattended delegated tokens.** MFA, compliant-device, sign-in-frequency and location policies can silently invalidate a refresh token or block non-interactive use. *Recommendation:* agree a dedicated policy for the agent group with the identity team in M0, test token lifetime empirically, and set `reauth_warning_days` from the result.
15. **Agent users are indistinguishable from humans unless you make them distinguishable.** Naming convention, an `agent` attribute/group, and GitHub rulesets that route approval to human teams keep separation of duties intact. Each agent also consumes licenses (GitHub seat, Microsoft 365/Teams) ⚠️.
16. **Account-based credentials change the Okta story.** Okta now directly gates AWS and ServiceNow only; GitHub and Microsoft are gated by account state plus Secrets Manager custody. Say this plainly to risk and audit and publish the §13 windows.

## 16. Open questions

1. Which OS(es) will agent hosts run? (Windows excluded for v1.)
2. Can Hermes re-read MCP headers/config without restart? Does it let us set per-command environment or PATH shims?
3. Does the org require signed commits? Are agent approvals allowed to count toward required reviews? Is the GitHub CLI's OAuth app (or another OAuth app) permitted for EMU users, and what is the PAT policy (max lifetime, approval, classic PATs)?
4. What is the ServiceNow release, and is the third-party-token flow enabled and approved by your ServiceNow platform team?
5. Atlassian: is API-token auth for Rovo MCP approved by the org admin? Which tools do you need that API-key scopes cannot provide?
6. Okta: license for API Access Management, custom AS count, ES256 acceptance, minimum token lifetime, status of Agent SSO / Okta for AI Agents.
7. Where do per-agent resources get created (Terraform pipeline? ServiceNow update sets)? Who approves onboarding?
8. Log destination and retention for daemon audit events.
9. Mailboxes: licensed user mailbox per agent (required for Teams and delegated access); is Exchange hybrid, and who creates the AD/Entra objects and assigns Teams licenses?
10. Is Agent 365 / Entra Agent ID licensed in your tenant, and is the preview dependency acceptable for the P2 spike?
11. Entra: is it federated to Okta or password-synced from AD? Who can sign in as the agent user to complete the one-time device-code enrollment (MFA factors, break-glass), and what Conditional Access policy will apply to the agent group?

## 17. CI/CD and release requirements

Applies to this repository only; the Go repositories in the set (`agent-okta-d`, `agent-cli-core`, `snow-cli`, `outlook-cli`, `teams-cli`) use the same pipeline shape so a pipeline change is made once and copied. Pipelines are GitHub Actions workflows under `.github/workflows/`. The scaffolded `ci.yml` is a starting point and must be brought in line with this section. Items marked ⚠️ are not confirmed against vendor documentation and need a spike before the pipeline depends on them.

**Terminology.** *CI* verifies a change. *CD* produces and publishes a **release**: a semver-versioned set of signed artifacts. **Publishing a release is the whole of "deploy" in this section.** Rolling a release out to agent hosts, harness images or AWS accounts is the swarm owner's job (see REL-12).

### 17.1 Continuous integration

| ID | Requirement |
|---|---|
| BLD-1 | CI runs on **every pull request targeting `main`** and **on demand** (`workflow_dispatch`, optionally against a chosen ref). CI also runs as the first stage of every release (REL-9), so nothing is released untested. |
| BLD-2 | Checks: `gofmt -l .` is empty; `go mod tidy` leaves no diff; `go vet ./...`; `golangci-lint` at a pinned version; `go test -race ./...`; `govulncheck ./...`. |
| BLD-3 | Every release target (REL-1) is **cross-compiled on each PR**, so a portability break is found before merge, not at release time. |
| BLD-4 | PR CI needs **no credentials and no network access to real systems**: tests use fakes, mock endpoints and fake clocks. Integration tests against an Okta sandbox, AWS test account or KMS key run **only on demand** in a separate workflow, using environment-scoped, short-lived credentials obtained by GitHub OIDC, never repository secrets holding long-lived keys. |
| BLD-5 | The CI workflow is a **required status check** on `main` once branch protection is enabled. Branch protection is not configured yet; enabling it is a separate step. |
| BLD-6 | Workflows use least privilege (`permissions: contents: read` for CI), pin the Go version from `go.mod`, and pin third-party actions to a version or commit SHA. |

### 17.2 Release targets and artifacts

| ID | Target | Build | Artifact |
|---|---|---|---|
| REL-1a | **macOS, Apple silicon** | `darwin/arm64` | `.tar.gz` containing the `agent-okta-d` binary, signed and notarized with an Apple Developer ID (§12 already requires Apple notarization and `cosign`). The macOS Keychain and Secure Enclave signers (§4, topology B) may need cgo, which means the darwin build runs on a macOS runner, not a cross-compile ⚠️. |
| REL-1b | **Windows via WSL** | `linux/amd64` (and `linux/arm64` for WSL on Arm, see 17.7) | `.tar.gz`; WSL runs Linux binaries, so **this is the Linux build** and no native Windows `.exe` is produced. Native Windows is not a target. |
| REL-1c | **Linux, AWS-hosted container** | `linux/amd64` and `linux/arm64` (Graviton) | Multi-arch **OCI image** `ghcr.io/stainedhead/agent-okta-d:vX.Y.Z`, non-root, minimal base, plus the same Linux binaries as `.tar.gz` |

Common to all targets:

- REL-2. Each release also publishes `SHA256SUMS`, an SBOM (SPDX or CycloneDX), a build-provenance attestation, and a signature for every artifact. Linux and container artifacts are signed with `cosign` keyless signing from the workflow's GitHub OIDC identity ⚠️. The install documentation in `user-docs/` states how to verify them.
- REL-3. Builds are reproducible as far as Go allows: pinned toolchain, `-trimpath`, `CGO_ENABLED=0` where possible, and a build timestamp taken from the commit.
- REL-4. The binary reports its version (`agent-okta-d version`: semver, commit, build date), stamped with `-ldflags`. `agent-okta-d doctor` also reports the version, and the audit log records it at start-up.
- REL-4a. For the daemon the image is the **sidecar** deployment (topology A) and the tarballs are the desktop and VM installs (topologies B and C). Each tarball includes the service definition for its platform (macOS LaunchDaemon plist, systemd unit); the daemon and the agent must run as different OS users, so the install steps must refuse to run the daemon as the agent's user (§4, §15).

### 17.3 Versioning

| ID | Requirement |
|---|---|
| REL-5 | Releases follow **semantic versioning** (`MAJOR.MINOR.PATCH`). The git tag `vX.Y.Z` on `main` is the release identity. Tags are immutable: a version is never re-tagged or re-published. |
| REL-6 | Releases start at `0.1.0` and stay `0.y.z` while this PRD is a draft. `1.0.0` is cut by an explicit decision, never automatically. |
| REL-7 | The bump is taken from a **PR label** (`release:major`, `release:minor`, `release:patch`). An unlabeled PR that changes shipped code defaults to `patch`. A PR that touches only `docs/`, `user-docs/`, `specs/`, `*.md` or `INTENT.md` does **not** cause a release. `pkg/client` (§9) is part of the same Go module, so it takes the same version. A breaking change to `pkg/client` is a `major` bump, and from `v2` the module path needs the `/v2` suffix. `agent-cli-core` (whose `auth` package wraps `pkg/client`) pins a released `pkg/client` version, and the `snow`, `outlook` and `teams` CLIs get it transitively through the core. |

### 17.4 Continuous delivery

| ID | Requirement |
|---|---|
| REL-8 | CD runs **on merge of a pull request to `main`** and **on demand** (`workflow_dispatch` with a `bump` of `major`, `minor` or `patch`, an optional explicit `version`, and a `dry_run` option that builds and verifies but publishes nothing). |
| REL-9 | Stages, in order: CI gate (all of 17.1), compute version, cross-build every target, package, checksum, SBOM, sign and attest, **smoke-verify**, publish. Publishing creates the tag, a GitHub Release with notes generated from merged PR titles, and pushes the container image tagged `vX.Y.Z` and `vX.Y`. No `latest` tag is relied on; consumers pin a version. |
| REL-10 | Smoke-verify runs the built artifact before anything is published: the `linux/amd64` binary and the container image on a Linux runner, the `darwin/arm64` binary on an Apple-silicon runner. Each must run `agent-okta-d version` and report the expected version. |
| REL-11 | **All-or-nothing:** if any target fails to build, sign or verify, nothing is published. A failed run is safe to re-run, and a version is never published twice. |
| REL-12 | CD **does not roll out** a release. It does not deploy to AWS accounts, restart daemons, or rebuild harness images. The harness images in `agentic-team-w-paperclip` are intended to consume a released artifact by pinned version ⚠️ (to be agreed with that repository), rather than build this tool from source. |
| REL-13 | The release job gets only what it needs (`contents: write`, `packages: write`, `id-token: write`, attestations) from a protected `release` environment. Apple signing material lives only in that environment's secrets. On-demand runs require write access to the repository, and a `major` bump on demand should require a reviewer approval on the environment. No long-lived cloud credentials are stored in the repository. |
| REL-14 | A bad release is not deleted. It is superseded by a newer patch release and marked as withdrawn in its release notes; its tags and images stay in place. |

### 17.5 Repository-specific requirements

- **Release contents:** the `agent-okta-d` binary, the service definitions above, a sample configuration with placeholder values only (never real tenant identifiers or keys), and the `pkg/client` module tag.
- **Key custody in CI:** no signing key for Okta, AWS KMS, Keychain or TPM ever exists in the pipeline. Signer back ends are tested with fakes in PR CI.
- **Exposure drill:** the kill-switch drill (§13, M5) is a manual, on-demand activity and is not part of release CD.
- **Harness integration:** whether Hermes can consume the daemon's outputs as §16 question 2 asks is confirmed in M0, not by the pipeline.

- **Importable `pkg/client` (DEP-1).** `pkg/client` must be importable at a released semver tag of this module. The first tagged release (even `0.1.0`, containing only `pkg/client`) must exist before `agent-cli-core` can compile against it, so it comes early in the delivery plan, ahead of the daemon being functionally complete.
- **Breaking changes (DEP-2).** A breaking change to `pkg/client` is a `major` bump (REL-7; from `v2` the module path needs `/v2`). The downstream compatibility check lives in `agent-cli-core`'s CI, which must catch such a break; this repository does not build the consumers.
- **CI token and visibility (DEP-3).** This repository depends on no other repository in the set, so its CI needs no dependency-fetch token step, and its workflows keep `permissions: contents: read`. `agent-cli-core` and the CLIs fetch this module in their CI with the dynamic `GITHUB_TOKEN` and `packages: read`. ⚠️ Unconfirmed: `GITHUB_TOKEN` is scoped to the repository running the workflow, so if this repository is ever made private it must be published through GitHub Packages with the consumer repositories granted read on the package. Decide this before any visibility change.

### 17.6 Milestone placement

BLD-1 to BLD-6 are in place before the first milestone that merges Go code. The release pipeline (REL-1 to REL-14) is in place before the first tagged build, and no later than the first milestone that produces a runnable binary. Release signing and notarization may land later, in the hardening milestone, but unsigned builds are labelled pre-release until then. The first `pkg/client` tag (DEP-1) is cut early, before M1 completes, because `agent-cli-core` is blocked on it; it needs only BLD-1 to BLD-6 and a tag, not the full release pipeline (REL-1 to REL-14).

### 17.7 Open items (CI/CD)

1. **Apple signing.** Is an Apple Developer ID and notarization account available for CD? Until it is, darwin artifacts carry only the `cosign` signature and users must clear the quarantine attribute themselves ⚠️.
2. **Registry.** `ghcr.io` is assumed, matching `agentic-team-w-paperclip`. Should images also be pushed to Amazon ECR for the AWS-hosted container case?
3. **What "deploy" means.** This section treats it as publishing a release (REL-12). Confirm that no automatic rollout into an AWS environment is wanted.
4. **Version bump rule.** PR labels are assumed (REL-7). Conventional commits are the alternative.
5. **WSL on Arm.** Is `linux/arm64` for WSL wanted, or `linux/amd64` only?
6. **Shared pipeline.** Should the common workflow steps live in one reusable workflow? `agent-cli-core` is its own repository (https://github.com/stainedhead/agent-cli-core), so a reusable workflow could live there or in a dedicated repository; that part stays open and is not decided here.
7. **WSL service support.** Running the daemon's service definition under WSL needs systemd in the WSL distribution ⚠️; confirm before documenting it as supported. Applies only where this tool installs a service.

## Appendix A — Sources consulted

- Okta: [Implement OAuth for Okta with a service app](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/) · [Set up OAuth for API access](https://developer.okta.com/docs/guides/set-up-oauth-api/main/) · [Authorization servers](https://developer.okta.com/docs/concepts/auth-servers/) · [Authorization Servers API](https://developer.okta.com/docs/reference/api/authorization-servers/) · [Org AS requires private_key_jwt (dev forum)](https://devforum.okta.com/t/clientid-and-client-secret-rejected-with-error/32886) · [2026 release notes](https://developer.okta.com/docs/release-notes/2026-okta-identity-engine/) · [AI agent token exchange](https://developer.okta.com/docs/guides/ai-agent-token-exchange/secret/main/) · [Agent SSO announcement](https://www.okta.com/newsroom/press-releases/okta-brings-first-class-identity-to-ai-agents-with-agent-sso/) · [okta-aws-cli](https://github.com/okta/okta-aws-cli)
- AWS: [AWS CLI role with web identity](https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-role.html) · [AssumeRoleWithWebIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html) · [web_identity_token_file](https://docs.aws.amazon.com/sdkref/latest/guide/setting-global-web_identity_token_file.html) · [OIDC thumbprint change](https://github.com/hashicorp/terraform-provider-aws/issues/32480) · [OIDC trust-policy conditions (Wiz)](https://www.wiz.io/blog/avoiding-mistakes-with-aws-oidc-integration-conditions) · [aws-cdk #25870](https://github.com/aws/aws-cdk/issues/25870)
- GitHub (v0.2): [PAT policies for enterprises](https://docs.github.com/en/enterprise-cloud@latest/admin/enforcing-policies/enforcing-policies-for-your-enterprise/enforcing-policies-for-personal-access-tokens-in-your-enterprise) · [Credential types](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-programmatic-access-to-your-organization/github-credential-types) · [EMU account abilities and restrictions](https://docs.github.com/en/enterprise-cloud@latest/admin/managing-iam/understanding-iam-for-enterprises/abilities-and-restrictions-of-managed-user-accounts)
- GitHub (superseded v0.1 App design): [Generating an installation access token](https://docs.github.com/en/enterprise-cloud@latest/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app) · [Authenticating as an installation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation) · [Bot identity/bypass discussion](https://github.com/orgs/community/discussions/43460)
- ServiceNow: [OAuth inbound](https://www.servicenow.com/docs/r/zurich/platform-security/authentication/oauth-inbound.html) · [Federated token authentication (community)](https://www.servicenow.com/community/platform-privacy-security-blog/federated-token-authentication-for-servicenow-api-access-inbound/ba-p/3367827) · [OIDC provider for third-party tokens](https://www.servicenow.com/docs/r/oJu9n0q6rU~F9UHAnNCt5w/DWASCzLZOp2AjTW1J252Aw) · [Third-party ID token configuration](https://www.servicenow.com/docs/bundle/zurich-platform-security/page/integrate/machine-identity/task/configure-a-third-party-id-token.html) · [OAuth JWT bearer endpoint](https://www.servicenow.com/docs/r/xanadu/platform-security/authentication/create-jwt-endpoint.html) · [ServiceNow MCP/IdP configuration](https://www.servicenow.com/docs/r/XRgEFx7nPN6ciT_BBIvnbg/wHMdBoDSi6AUH2QGt19rhA)
- Atlassian: [Rovo MCP authentication and authorization](https://developer.atlassian.com/cloud/rovo-mcp/guides/authentication-and-authorization/) · [Configuring API token authentication](https://developer.atlassian.com/cloud/rovo-mcp/guides/configuring-authentication-via-api-token/) · [Control MCP server settings](https://support.atlassian.com/security-and-access-policies/docs/control-atlassian-mcp-server-settings/)
- Microsoft: [Workload identity federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation) · [FIC considerations](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-considerations) · [Send chat message (delegated vs application permissions)](https://learn.microsoft.com/en-us/graph/api/chat-post-messages?view=graph-rest-1.0) · [Graph delegated access and offline_access](https://learn.microsoft.com/en-us/graph/auth-v2-user) · [ROPC limitations](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth-ropc) · [Agent 365 identity](https://learn.microsoft.com/en-us/microsoft-agent-365/developer/identity) · [Graph CLI retirement](https://github.com/microsoftgraph/msgraph-cli/issues/585)
