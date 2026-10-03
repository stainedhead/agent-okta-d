// Package client is the Go client for the agent-okta-d local API. It is the
// contract with agent-cli-core and depends on the standard library only; it
// must never import anything under internal/ (ADR-C).
//
// Wire type names (workstream WS-A defines these in this package, with the
// JSON shapes pinned by internal/domain/testdata/wire/*.json):
//
//	Credential  <- domain.WireCredential  {token_type, access_token, issued_at, expires_at, audience}
//	Status      <- domain.WireStatus      {state, providers[]}
//	ProviderStatus <- domain.WireProviderStatus {provider, state, expires_at, last_error, retry_after_seconds}
//	Identity    <- domain.WireIdentity    {agent_id, okta_client_id, kid, daemon_version, api_version}
//	error body  <- domain.WireError       {error, state, retry_after_seconds}
//
// Error mapping (HTTP status + body "error" code): reauth_required (401) to
// ErrReauthRequired, revoked (403) to ErrRevoked, unauthorized (403) to
// ErrUnauthorized, not_configured (404) to ErrNotConfigured, degraded (503,
// Retry-After) to ErrDegraded, connection failure to ErrDaemonUnavailable.
// Code is decided by the body "error" field first, status second.
//
// Usage:
//
//	c := client.New()                       // socket: AGENT_OKTA_D_SOCKET, else platform default
//	cred, err := c.Credential(ctx, "aws")   // cred.AccessToken prints redacted; use Reveal()
//	if errors.Is(err, client.ErrDegraded) { d, _ := client.RetryAfter(err); ... }
//
// Test code can run against clienttest, an in-process fake daemon.
package client
