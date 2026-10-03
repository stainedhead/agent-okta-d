# User documentation

Guides for adopting, configuring and using `agent-okta-d`. This directory holds only user material; design and requirements live elsewhere in the repository.

- [Getting started](getting-started.md): build, minimal setup, first run, what works in this build.
- [Configuration reference](configuration.md): every setting, default and validation rule.
- [Usage examples](usage.md): each command and each provider.
- [Go client library](client-library.md): using `pkg/client` from your own program or tests.
- [Troubleshooting](troubleshooting.md): exit codes, error messages and fixes.

## Read this first: verification status

The daemon has been tested only against in-process fakes. It has not been run against a real Okta, AWS, GitHub, ServiceNow, Microsoft 365 or Atlassian tenant. Statements about vendor behavior below are marked **UNVERIFIED** where they depend on an unconfirmed assumption; the register is in [`../docs/assumptions.md`](../docs/assumptions.md). Treat a first real-tenant run as a pilot.

## Limitations of this build

- Only the `file` signer works. The `kms`, `keychain` and `tpm` signers exist as code but cannot start in the shipped binary.
- Only the `file-encrypted` secret store works (needs an RS256 signer). `aws-secretsmanager` and `keychain` stores cannot start.
- The `atlassian` provider needs `aws-secretsmanager` and therefore cannot start in this build.
- `doctor` cannot run the AWS STS probe (no STS client in this build).
- No release artifacts exist: build from source. Release workflows are not part of this work.
