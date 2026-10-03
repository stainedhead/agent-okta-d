# Getting started

## 1. Build

Requires the Go toolchain version in `go.mod`.

```
make build            # writes bin/agent-okta-d
./bin/agent-okta-d version
```

`go build ./cmd/agent-okta-d` works too. Supported targets are darwin/arm64, linux/amd64 and linux/arm64 (static, `CGO_ENABLED=0`). Native Windows is not supported; on Windows use WSL2 with the Linux build (**UNVERIFIED**, A-11).

## 2. Plan the OS principals

The daemon and the agent must run as different OS users with different primary groups. Create a user and group for the daemon (for example `agentd`), a group for agents that may call it (for example `agentd-clients`), and put the agent user in that group. List that group in `ipc.allow_gids`. The daemon refuses to start if its own primary gid is in `ipc.allow_gids`, and warns if it runs as root.

## 3. Create the signing key (file signer)

```
openssl genrsa -out /etc/agent-okta-d/agent.key 2048
chmod 0400 /etc/agent-okta-d/agent.key     # owned by the daemon user; no group/other bits
```

The file signer rejects a key file with any group or other permission bits. It is meant for development; hardware-backed signers are not available in this build.

## 4. Write a minimal config

```yaml
agent:
  id: agent-007
  environment: dev
okta:
  org_url: https://example.okta.com
  client_id: 0oaEXAMPLE
  signer:
    type: file
    key_id: /etc/agent-okta-d/agent.key
    kid: agent-007-key-1
providers:
  servicenow:
    instance_url: https://example.service-now.com
    authorization_server: agents-snow
    scope: snow.read
ipc:
  allow_gids: [agentd-clients]
```

Save as `/etc/agent-okta-d/config.yaml` (or point `--config` / `$AGENT_OKTA_D_CONFIG` at it). Every setting is in the [configuration reference](configuration.md).

## 5. Register the key in Okta

```
agent-okta-d enroll okta --config /etc/agent-okta-d/config.yaml
```

This prints the public key as a JWK plus a checklist: create an Okta API Services app with "Public key / Private key" authentication, add the JWK, grant the scopes of each authorization server, restrict the access policy to this client, then set `okta.client_id`. Whether Okta accepts ES256 keys is **UNVERIFIED** (A-01); RS256 is the default.

## 6. Check, then run

```
agent-okta-d doctor --config /etc/agent-okta-d/config.yaml
agent-okta-d run    --config /etc/agent-okta-d/config.yaml     # as the daemon user, under your supervisor
```

`doctor` checks the version, config warnings, user separation, the signer, clock skew against Okta, and a mint plus end-to-end probe for every provider. Each line is `ok`, `warn`, `fail` or `skip`.

The socket defaults to `/run/agentd/<agent.id>/agentd.sock` (`/var/run/agentd/<agent.id>/agentd.sock` on macOS); the daemon creates the socket (mode 0660, group set to the allowed group when `ipc.allow_gids` has one entry; mode 0666 with several, where peer credentials decide) and a pidfile beside it. If the directory does not exist the daemon creates it with mode 0750 owned by the daemon user, which an agent in another group cannot traverse. Pre-create it yourself, owned by the daemon user, with the allowed group and mode 0750, so the agent can reach the socket. Supervise the process yourself (systemd or launchd); exit code 77 (revoked) and 78 (config) mean "do not restart-loop". No unit files are shipped.

## 7. Use it as the agent

```
export AGENT_OKTA_D_SOCKET=/run/agentd/agent-007/agentd.sock
agent-okta-d status
agent-okta-d token servicenow
```

Continue with [usage examples](usage.md).
