# Configuration reference

The daemon reads one YAML file: `--config FILE`, else `$AGENT_OKTA_D_CONFIG`, else `/etc/agent-okta-d/config.yaml`. Unknown keys are rejected. Errors name the offending field and never echo its value; every configuration error exits 78. The file must hold no secrets (the git credential helper runs as the agent user and may need to read it).

Duration-like settings are integers in seconds. `agent.id` is used in default paths, as the AWS role session name, and in logs.

## agent

| Key | Required | Default | Notes |
|---|---|---|---|
| `id` | yes | none | letters, digits, `-`, `_`, `.`; must not start with `.` |
| `environment` | no | empty | free text label |

## okta

| Key | Required | Default | Notes |
|---|---|---|---|
| `org_url` | yes | none | must be an `https` URL |
| `client_id` | yes | none | the agent's Okta API Services app |
| `signer.type` | yes | none | `file`, `kms`, `keychain`, `tpm`. Only `file` works in this build |
| `signer.key_id` | yes for `file` and `kms` | none | for `file`: path of the PEM private key (PKCS#8, PKCS#1 RSA or SEC1 P-256; RSA at least 2048 bits; no group/other permission bits). For `keychain`/`tpm`: key reference |
| `signer.alg` | no | `RS256` | `RS256` or `ES256`. ES256 is accepted but flagged with a warning: Okta acceptance is **UNVERIFIED** (A-01). The alg must match the key file |
| `signer.kid` | yes | none | key id registered in Okta |
| `authorization_servers` | no | none | map from authorization server name to `{id, audience}`. A name with no entry is used as its own id. Default audiences: `aws` is `sts.amazonaws.com`, `servicenow` is the instance URL |

## providers

Each provider is enabled by the presence of its section. With no providers the daemon serves only status and identity.

### providers.aws

| Key | Required | Default | Notes |
|---|---|---|---|
| `authorization_server` | yes | none | Okta authorization server name |
| `scope` | yes | none | |
| `token_file` | yes (defaulted) | `/run/agentd/<id>/aws-web-identity.jwt` (`/var/run/...` on macOS) | the web-identity token file |
| `file_mode` | no | `0440` | octal string |
| `role_arn` | yes | none | role the AWS tooling assumes |
| `role_session_name` | no | `agent.id` | |
| `region` | yes | none | |

### providers.github

| Key | Required | Default | Notes |
|---|---|---|---|
| `api_base` | no | `https://api.github.com` | https URL; use the GHES/EMU API base otherwise |
| `mode` | yes | none | `pat` or `oauth_device` |
| `login` | yes | none | the agent's GitHub user, also the git username |
| `oauth_client_id` | no | empty | for `oauth_device`; empty uses a GitHub CLI app default that is flagged **UNVERIFIED** (A-06) |
| `store.type` | yes | none | `file-encrypted` works; `aws-secretsmanager` and `keychain` do not in this build |
| `store.secret_id` | yes | none | name of the stored credential |
| `store.path` | no | `/var/lib/agentd/<id>/secrets.enc` (`/var/db/agentd/<id>/secrets.enc` on macOS) | file-encrypted store file; the first configured path is used for all |
| `expiry_warning_days` | no | `30` | `doctor` warns inside this window |
| `git_identity.name`, `git_identity.email` | no | name: login; email: noreply address from `GET /user` | used by `configure git` |
| `probe_repo` | no | empty | `owner/name` for the doctor read check |

### providers.servicenow

| Key | Required | Default | Notes |
|---|---|---|---|
| `instance_url` | yes | none | https URL; also the default token audience |
| `authorization_server` | yes | none | |
| `scope` | yes | none | |
| `min_ttl_seconds` | no | `120` | refresh synchronously when less remains |

### providers.msgraph

| Key | Required | Default | Notes |
|---|---|---|---|
| `tenant_id` | yes | none | |
| `app_client_id` | yes | none | public client app for the delegated flow |
| `upn` | yes | none | the agent user's principal name; enrollment checks it |
| `scopes` | yes | none | list; at least one |
| `store.type`, `store.secret_id`, `store.path` | yes (type, id) | none | as for github |
| `reauth_warning_days` | no | `14` | |
| `probe_other_user` | needed by `doctor` | empty | a mailbox the agent must not reach; the doctor expects 403. Without it the msgraph probe reports a configuration failure |

### providers.atlassian

Cannot start in this build (needs `aws-secretsmanager`).

| Key | Required | Default | Notes |
|---|---|---|---|
| `type` | no | `secret` | only `secret` |
| `source` | yes | none | only `aws-secretsmanager` |
| `secret_id` | yes | none | |
| `sink.file` | yes (defaulted) | `/run/agentd/<id>/atlassian.key` | |
| `sink.mode` | no | `0440` | octal string |
| `interval_seconds` | no | `900` | re-fetch interval |

## refresh

| Key | Default | Rule |
|---|---|---|
| `fraction` | `0.5` | > 0 and < 1 |
| `jitter` | `0.05` | >= 0 and < 1 |
| `min_margin_seconds` | `120` | >= 0 |

The AWS provider always refreshes at 0.45 plus at most 0.05 jitter.

## ipc

| Key | Required | Default | Notes |
|---|---|---|---|
| `socket` | defaulted | `/run/agentd/<id>/agentd.sock` (`/var/run/agentd/<id>/agentd.sock` on macOS) | |
| `allow_gids` | yes | none | at least one group name or numeric gid; fail closed. The first group name is also the group given read access to credential files |

## log

| Key | Default | Allowed |
|---|---|---|
| `level` | `info` | `debug`, `info`, `warn`, `error` |
| `format` | `json` | `json` |
| `destination` | `stderr` | `stderr`, `stdout` or an absolute file path (opened append, mode 0600) |

Tokens, client assertions and key material are never logged; secret values pass through a redaction layer.

## Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `AGENT_OKTA_D_CONFIG` | all commands that read config | config file path |
| `AGENT_OKTA_D_SOCKET` | client commands and `pkg/client` | socket path (overridden by `--socket`) |
