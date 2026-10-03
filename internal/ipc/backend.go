// Package ipc is the daemon's local API: an HTTP server on a unix domain
// socket (PRD section 11, FR-7). Callers are authenticated by peer credentials
// and allow-listed by gid per provider. It fails closed: any peer-credential
// failure, unknown gid or unknown path is a refusal.
package ipc

import (
	"context"
	"errors"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// ErrNotConfigured is returned by a Backend for an unknown or disabled
// provider. It maps to 404 not_configured.
var ErrNotConfigured = errors.New("provider not configured")

// Backend is what the handlers need from the credential cache (the consumer
// side interface; the cache package satisfies it through a small adapter in
// cmd wiring).
type Backend interface {
	// Credential returns the current credential for provider, refreshing
	// synchronously when it is below min_ttl. Errors are classified with the
	// domain taxonomy: ErrRevoked -> 403, ErrReauthRequired -> 401,
	// ErrNotConfigured -> 404, ErrTransient -> 503 (a domain.RetryAfter hint is
	// honoured), anything else -> 500.
	Credential(ctx context.Context, provider string) (domain.Credential, error)
	// Refresh forces a refresh and returns the new credential, with the same
	// error classification.
	Refresh(ctx context.Context, provider string) (domain.Credential, error)
	// Status returns the per-provider states. It never carries secrets.
	Status(ctx context.Context) domain.WireStatus
}
