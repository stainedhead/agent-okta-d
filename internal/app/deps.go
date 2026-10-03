package app

import (
	"context"
	"log/slog"

	"github.com/stainedhead/agent-okta-d/internal/cache"
	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// deps is the domain.Deps handed to providers.
type deps struct {
	clock  domain.Clock
	okta   domain.OktaTokenSource
	cache  *cache.Cache
	stores *storeSet
	log    *slog.Logger
	audit  domain.AuditSink
}

var _ domain.Deps = (*deps)(nil)

func (d *deps) Clock() domain.Clock          { return d.clock }
func (d *deps) Okta() domain.OktaTokenSource { return d.okta }
func (d *deps) Logger() *slog.Logger         { return d.log }
func (d *deps) Audit() domain.AuditSink      { return d.audit }

func (d *deps) Store(name string) (domain.SecretStore, error) { return d.stores.Store(name) }

func (d *deps) Credential(ctx context.Context, provider string) (domain.Credential, error) {
	if d.cache == nil {
		return domain.Credential{}, domain.ErrNotFound
	}
	return d.cache.Credential(ctx, provider)
}

// noOkta is the token source when no Okta-backed provider is configured.
type noOkta struct{}

func (noOkta) Token(context.Context, domain.OktaTokenRequest) (domain.OktaToken, error) {
	return domain.OktaToken{}, domain.NewConfigError("okta", "no Okta-backed provider (aws, servicenow) is configured")
}

// guarded registers static secrets with the scrubber the first time a
// provider mints them (defence in depth behind SecretString; JWT-shaped
// tokens are already caught by the scrubber's pattern).
type guarded struct {
	domain.Provider
	scrub *domain.Scrubber
}

func (g guarded) Mint(ctx context.Context, d domain.Deps) (domain.Credential, error) {
	c, err := g.Provider.Mint(ctx, d)
	if err == nil && c.Kind == domain.KindStaticSecret {
		g.scrub.Add(c.Value)
	}
	return c, err
}

// unwrap returns the provider behind guarded.
func unwrap(p domain.Provider) domain.Provider {
	if g, ok := p.(guarded); ok {
		return g.Provider
	}
	return p
}
