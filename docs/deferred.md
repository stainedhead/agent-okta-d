# Deferred work, unverified items and root skill update

Status of what was not built or not verified in this repository. Everything here was built and tested against fakes only: no live system, tenant, AWS account or credential was used.

## Deferred items and rationale

| Item | Why deferred | What closes it |
|---|---|---|
| Real AWS SDK adapters: `KMSAPI` (KMS signer), `SecretsManagerAPI`, `STSClient` | Cannot be verified without a live (sandbox) AWS account; fakes-only tests would say nothing about real SDK behavior. The SDK dependency also needs its own `CGO_ENABLED=0` three-target build and binary-size assessment. `DefaultEnv` leaves them nil, so configs needing them exit 78 and the `doctor` aws probe fails. This also blocks the `atlassian` provider (secret store). | A sandbox AWS account, production adapters selectable through `DefaultEnv`, and a contract test reusable against the sandbox. |
| macOS Keychain signer and store; Linux TPM signer (stubs return `ErrConfig`) | Need real hardware and OS key APIs (Secure Enclave, TPM 2.0), and possibly cgo (A-12). Cannot be exercised in CI. | Hardware-backed spike on a Mac and a TPM host; ES256 acceptance by Okta (A-01) is a prerequisite for the Secure Enclave. |
| M0 spikes (real tenants) | Require real Okta, GitHub EMU, ServiceNow, Entra and AWS tenants. Replaced by the checklist in `m0-spike-checklist.md`, which has not been run. | Run the checklist and update `assumptions.md`. |
| M6 Okta roadmap evaluation | Depends on vendor roadmap and M0 results. | Evaluate after M0. |
| Entra Agent User spike | Needs an Entra tenant with the preview feature. | Spike, then decide whether msgraph moves off the delegated user model. |
| P2 items: metrics (FR-12), hot reload (FR-13; `SIGHUP` is logged and ignored), memory hygiene (FR-14), GH-10/11/12, MG-7/8, AT-2c, AWS-6, SN-5 | Lower priority than the identity path. | Individual follow-up tasks. |
| Release workflow (build, sign, notarize, publish) | Out of scope; only CI exists. | Separate release work. |
| Real-crash test for AC-007 (kill between write and rename) | Covered only by injected rename failures. | Optional process-kill test. |

## Unverified against a real tenant

All vendor behavior in `assumptions.md` (A-01 to A-12 and A-20) is unverified. In particular:

- Okta accepts ES256 `private_key_jwt` assertions (A-01), minimum access-token lifetime (A-02), `sub` of client-credential tokens (A-03), revocation of issued tokens (A-04).
- GitHub: PAT expiry header and noreply email form (A-05), GitHub CLI OAuth app for EMU users (A-06), SCIM deprovisioning timing (A-08).
- Microsoft Graph refresh-token lifetime and Conditional Access behavior (A-07).
- Hermes reloading MCP secrets (A-09), KMS signature conversion (A-10), WSL2 service support (A-11), macOS notarization and cgo for Keychain (A-12).
- Atlassian Rovo MCP secret handling and ServiceNow token acceptance have never been exercised.
- Unix socket peer-credential behavior is tested on Linux and macOS runners only through fakes of the peer; Linux supplementary groups are not part of peer credentials (documented in user-docs).

## Root skill update needed

Owner: whoever maintains `skills/agent-okta-d.md` in https://github.com/stainedhead/agentic-teams (manual PR; this repo does not touch the root repo). Given what was built, the skill should:

1. State the `token` exit codes: 0 ok, 1 failure, 2 usage, 3 daemon unreachable, 77 revoked, 78 configuration. On 77 the agent must stop and not retry or restart the daemon.
2. Describe the `reauth_required` provider state: `status` exits non-zero and `token` fails for that provider until a human re-enrolls; the agent must not try to work around it.
3. Describe the revoked state precisely: a definitive rejection by Okta for one provider's client revokes the whole daemon (FR-R02 scopes this to client rejections), and credential files are removed.
4. List the agent-runnable commands only: `token`, `status`, `env github`, `credential-helper`, `configure git|gh|aws` as applicable. `doctor`, `revoke`, `enroll` and `run` are operator commands.
5. Say which credential forms stock tools receive (AWS web-identity token file, git credential helper and `GH_TOKEN`, Bearer for `snow`, Atlassian secret, Graph token) and that only the `file` signer and `file-encrypted` store work in this build, so agent setups cannot rely on KMS, Keychain, TPM, Secrets Manager or the `atlassian` provider yet.
6. Note that `token` prints the real secret and must never be logged, and that the socket is reached via `--socket` or `AGENT_OKTA_D_SOCKET`.
7. Carry the status caveat: implemented against fakes, never run against a real tenant.
