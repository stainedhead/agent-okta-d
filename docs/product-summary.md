# Product summary

`agent-okta-d` is a credential daemon for autonomous SDLC agents. It runs beside each agent host, holds the agent's Okta signing key out of the agent's reach, and turns short-lived Okta OIDC tokens into the credential forms that AWS, GitHub, ServiceNow, Atlassian and Microsoft 365 (Outlook, Teams) tooling already understands.

## Status (what is actually built)

The Go implementation exists and is covered by fake-based tests (no test needs a network or a credential). It has never been run against a real Okta, AWS, GitHub, ServiceNow, Microsoft or Atlassian tenant. Every vendor behavior that is not confirmed is listed in [`assumptions.md`](assumptions.md) and must be settled by the real-tenant checklist in [`m0-spike-checklist.md`](m0-spike-checklist.md).

| Area | State in this build |
|---|---|
| Daemon (`run`), unix socket API, peer-credential auth, cache and refresh scheduler, file sinks, audit and log redaction | Built, fake-tested |
| Providers: `aws`, `github`, `servicenow`, `msgraph`, `atlassian` (generic secret) | Built, fake-tested; vendor behavior unverified |
| Operator CLI: `run`, `token`, `status`, `doctor`, `revoke`, `env`, `credential-helper`, `configure aws/git/gh`, `enroll github/msgraph/okta`, `version` | Built |
| `pkg/client` Go library and `pkg/client/clienttest` fake daemon | Built, API snapshot pinned |
| Signer `file` (PEM key, RS256 or ES256) | Built; development use |
| Signers `kms`, `keychain`, `tpm` | Code present but NOT usable in the shipped binary (see Limitations) |
| Stores `file-encrypted` | Built (needs an RS256 signer) |
| Stores `aws-secretsmanager`, `keychain` | NOT usable in the shipped binary (see Limitations) |

## Limitations of this build

- **FR-R01 (deferred follow-up, needs a sandbox AWS account):** the AWS SDK adapters (KMS signing, Secrets Manager, STS) have no production implementation. The binary's default environment leaves them unset, so `okta.signer.type: kms`, `store.type: aws-secretsmanager` and the `atlassian` provider (which only supports `source: aws-secretsmanager`) fail at startup with exit 78 ("not available in this build"). `doctor` cannot run the AWS STS probe. Real adapters cannot be verified without live AWS, so they are tracked as a follow-up. Because the only working signer is `file`, `run` logs a WARN and `doctor` reports `signer-hardening: warn` whenever `signer.type: file` is used (the key stays on disk, readable by the daemon uid).
- The macOS Keychain / Secure Enclave and Linux TPM 2.0 signer backends, and the native Keychain secret store, are stubs that return a configuration error. The surrounding logic (JOSE encoding, key handling) is implemented and unit-tested against fakes, but no hardware backend exists.
- In practice the only end-to-end usable combination today is `signer.type: file` with the `aws`, `servicenow`, `github` and `msgraph` providers, using the `file-encrypted` store for `github` and `msgraph`.
- Release workflows (signing, notarization, packaging, publishing) are not part of this work. The only workflow is CI (`.github/workflows/ci.yml`).

See [`product-details.md`](product-details.md) for behavior, [`technical-details.md`](technical-details.md) for design and the `pkg/client` reference, and the deferred list at the end of `product-details.md`.
