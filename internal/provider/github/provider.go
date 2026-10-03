package github

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// MetaTokenExpiresAt is the local Credential.Meta key holding the underlying
// token's expiry (RFC 3339); the credential's own ExpiresAt is only the
// re-fetch horizon.
const MetaTokenExpiresAt = "token_expires_at"

// MetaMode is the local Credential.Meta key holding the credential mode.
const MetaMode = "mode"

// Provider is the github provider (GH-1, GH-2, GH-9). It never mints: it reads
// the agent's PAT or OAuth token from the configured secret store and serves
// it as a static-secret credential.
type Provider struct {
	cfg Config
	api *API

	mu      sync.Mutex
	deps    domain.Deps // remembered from Mint, used by Probe to re-fetch (GH-9)
	version string      // store version of the secret served last
}

var _ domain.Provider = (*Provider)(nil)

// New validates cfg and builds the provider.
func New(cfg Config) (*Provider, error) {
	cfg, err := cfg.Normalize()
	if err != nil {
		return nil, err
	}
	p := &Provider{cfg: cfg}
	p.api = &API{Base: cfg.APIBase, HTTP: cfg.HTTPClient}
	return p, nil
}

// Config returns the normalized configuration.
func (p *Provider) Config() Config { return p.cfg }

// Name implements domain.Provider.
func (*Provider) Name() string { return ProviderName }

// Sinks implements domain.Provider: the optional raw-token file.
func (p *Provider) Sinks() []domain.SinkSpec {
	if p.cfg.TokenFile == "" {
		return nil
	}
	return []domain.SinkSpec{{Path: p.cfg.TokenFile, Mode: 0o440, Format: domain.SinkRawNL}}
}

// Revoke implements domain.Provider. A static user credential has nothing to
// withdraw at GitHub; the kill switch is SCIM suspension (PRD 13).
func (*Provider) Revoke(context.Context, domain.Credential) error { return nil }

func (p *Provider) fetch(ctx context.Context, d domain.Deps) (Stored, string, error) {
	store, err := d.Store(p.cfg.StoreName)
	if err != nil {
		return Stored{}, "", err
	}
	v, err := store.Get(ctx, p.cfg.SecretID)
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return Stored{}, "", domain.Wrap(domain.ErrReauthRequired, errors.New("no github credential enrolled; run enroll github"))
	case errors.Is(err, domain.ErrTransient), errors.Is(err, domain.ErrConfig), errors.Is(err, domain.ErrAuthDefinitive):
		return Stored{}, "", err
	case err != nil:
		return Stored{}, "", domain.NewTransient(fmt.Errorf("reading github secret: %w", err), 0)
	}
	s, err := ParseStored(v.Value)
	if err != nil {
		return Stored{}, "", err
	}
	if s.Mode != "" && s.Mode != p.cfg.Mode {
		return Stored{}, "", domain.NewConfigError("providers.github.mode",
			fmt.Sprintf("configured %s but the stored credential was enrolled as %s", p.cfg.Mode, s.Mode))
	}
	return s, v.Version, nil
}

// Mint implements domain.Provider.
func (p *Provider) Mint(ctx context.Context, d domain.Deps) (domain.Credential, error) {
	s, ver, err := p.fetch(ctx, d)
	if err != nil {
		return domain.Credential{}, err
	}
	now := d.Clock().Now()
	horizon := now.Add(p.cfg.RefetchInterval)
	meta := map[string]string{
		domain.MetaAudience: p.cfg.APIBase,
		domain.MetaLogin:    p.cfg.Login,
		MetaMode:            string(p.cfg.Mode),
	}
	if s.Scope != "" {
		meta[domain.MetaScope] = s.Scope
	}
	if !s.ExpiresAt.IsZero() {
		if !now.Before(s.ExpiresAt) {
			return domain.Credential{}, domain.Wrap(domain.ErrReauthRequired, errors.New("stored github token has expired"))
		}
		meta[MetaTokenExpiresAt] = s.ExpiresAt.UTC().Format(time.RFC3339)
		if s.ExpiresAt.Before(horizon) {
			horizon = s.ExpiresAt
		}
	}
	c := domain.Credential{Kind: domain.KindStaticSecret, Value: domain.NewSecret(s.Token), IssuedAt: now, ExpiresAt: horizon, Meta: meta}
	if err := c.Validate(); err != nil {
		return domain.Credential{}, err
	}
	p.mu.Lock()
	p.deps, p.version = d, ver
	p.mu.Unlock()
	if msg, ok := p.ExpiryWarning(c, now); ok {
		d.Logger().Warn("github token "+msg, "provider", ProviderName, "login", p.cfg.Login)
	}
	return c, nil
}

// TokenExpiry classifies the underlying token's expiry carried in c (GH-6) and
// returns the time remaining.
func (p *Provider) TokenExpiry(c domain.Credential, now time.Time) (ExpiryState, time.Duration) {
	t, err := time.Parse(time.RFC3339, c.Meta[MetaTokenExpiresAt])
	if err != nil {
		return ExpiryUnknown, 0
	}
	return ExpiryStatus(t, now, p.cfg.ExpiryWarningDays), max(t.Sub(now), 0)
}

// ExpiryWarning returns a human sentence when the token is within the warning
// horizon or expired, for `status` and `doctor`.
func (p *Provider) ExpiryWarning(c domain.Credential, now time.Time) (string, bool) {
	st, rem := p.TokenExpiry(c, now)
	switch st {
	case ExpiryExpired:
		return "has expired; run enroll github", true
	case ExpiryWarn:
		return fmt.Sprintf("expires soon (%d days left); renew it and run enroll github", int(rem.Hours()/24)), true
	}
	return "", false
}

// Probe implements domain.Provider: GET /user must return the configured login
// (GH-7), then an optional read on ProbeRepo. On 401 it re-fetches the secret
// once and retries only if the store holds a different token; a second
// rejection is ErrReauthRequired (GH-9). 403/429 surface Retry-After.
func (p *Provider) Probe(ctx context.Context, c domain.Credential) error {
	token := c.Value
	u, err := p.api.User(ctx, token)
	if errors.Is(err, domain.ErrReauthRequired) {
		token, u, err = p.retryAfterRefetch(ctx, token, err)
	}
	if err != nil {
		return err
	}
	if !strings.EqualFold(u.Login, p.cfg.Login) {
		return domain.NewProviderError(ProviderName,
			fmt.Errorf("token belongs to %q but providers.github.login is %q", u.Login, p.cfg.Login))
	}
	if p.cfg.ProbeRepo != "" {
		return p.api.Repo(ctx, token, p.cfg.ProbeRepo)
	}
	return nil
}

func (p *Provider) retryAfterRefetch(ctx context.Context, old domain.SecretString, first error) (domain.SecretString, User, error) {
	p.mu.Lock()
	d := p.deps
	p.mu.Unlock()
	if d == nil {
		return old, User{}, first
	}
	s, ver, err := p.fetch(ctx, d)
	if err != nil {
		return old, User{}, err
	}
	fresh := domain.NewSecret(s.Token)
	if fresh.Equal(old) {
		return old, User{}, first
	}
	p.mu.Lock()
	p.version = ver
	p.mu.Unlock()
	u, err := p.api.User(ctx, fresh)
	return fresh, u, err
}

// Whoami resolves the user behind token (used by enroll and configure git).
func (p *Provider) Whoami(ctx context.Context, token domain.SecretString) (User, error) {
	return p.api.User(ctx, token)
}
