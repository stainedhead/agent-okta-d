# Go client library (pkg/client)

`github.com/stainedhead/agent-okta-d/pkg/client` is the Go client for the daemon socket. It uses only the standard library. The shared CLI core (`agent-cli-core`) wraps it for the `snow`, `outlook` and `teams` CLIs; use it directly for your own tools.

```go
c := client.New()                         // socket: client.WithSocketPath, else $AGENT_OKTA_D_SOCKET, else platform default
defer c.Close()

cred, err := c.Credential(ctx, "servicenow")
switch {
case errors.Is(err, client.ErrDegraded):
	d, _ := client.RetryAfter(err)        // wait d, then retry
case errors.Is(err, client.ErrReauthRequired):
	// an operator must run: agent-okta-d enroll <provider>
case errors.Is(err, client.ErrRevoked):
	// the daemon was revoked: stop
case errors.Is(err, client.ErrDaemonUnavailable):
	// socket missing, permission denied or timeout
case err != nil:
	// ErrUnauthorized, ErrNotConfigured, ErrInvalidResponse, or an *client.APIError (for example HTTP 500)
default:
	req.Header.Set("Authorization", cred.TokenType+" "+cred.AccessToken.Reveal())
}
```

Notes:

- Printing or logging `cred` or `cred.AccessToken` shows `[redacted]`; call `Reveal()` only where the token is used.
- Other calls: `Refresh(ctx, provider)`, `Status(ctx)`, `Identity(ctx)`. `WithTimeout(d)` changes the 5 second per-request default.
- The default socket path (`/run/agentd/agentd.sock`, `/var/run/agentd/agentd.sock` on macOS) differs from the daemon's default `ipc.socket`, which includes the agent id as a directory. Set `AGENT_OKTA_D_SOCKET` (or `WithSocketPath`) to the daemon's configured `ipc.socket`.
- `TokenType` is `Bearer` for bearer tokens, otherwise the credential kind (for example for static secrets).

## Testing without a daemon

`pkg/client/clienttest` runs an in-process fake daemon:

```go
srv := clienttest.New(t)                  // t is *testing.T; cleaned up automatically
srv.SetCredential("servicenow", clienttest.Credential{
	TokenType: "Bearer", AccessToken: "tok", IssuedAt: now, ExpiresAt: now.Add(time.Hour), Audience: "https://example.service-now.com",
})
srv.SetProviderError("github", clienttest.Error{Code: clienttest.CodeDegraded, State: "degraded", RetryAfter: 30 * time.Second})
c := client.New(client.WithSocketPath(srv.SocketPath()))
```

Other helpers: `SetRefreshed`, `SetGlobalError`, `SetRaw`, `SetStatus`, `SetIdentity`, `SetDelay`, `Requests`, `DeadSocketPath`. By default every provider answers `not_configured`.

## Compatibility

The exported API is pinned by a snapshot test: any change is a deliberate, versioned decision. Wire field names and error codes are fixed for API version `v1`. The module is pre-1.0 and no release has been published; pin to a commit.
