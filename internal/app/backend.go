package app

import (
	"context"
	"errors"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/cache"
	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/ipc"
)

// backend adapts the cache to ipc.Backend: it translates the cache errors to
// the classes the API maps (unknown provider -> ErrNotConfigured, degraded ->
// ErrTransient with a Retry-After hint) and builds the status document.
type backend struct {
	c     *cache.Cache
	clock domain.Clock
}

var _ ipc.Backend = backend{}

func (b backend) Credential(ctx context.Context, provider string) (domain.Credential, error) {
	c, err := b.c.Credential(ctx, provider)
	return c, mapCacheErr(err)
}

func (b backend) Refresh(ctx context.Context, provider string) (domain.Credential, error) {
	if err := b.c.Refresh(ctx, provider); err != nil {
		return domain.Credential{}, mapCacheErr(err)
	}
	c, err := b.c.Credential(ctx, provider)
	return c, mapCacheErr(err)
}

func mapCacheErr(err error) error {
	var de *cache.DegradedError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, domain.ErrNotFound):
		return ipc.ErrNotConfigured
	case errors.As(err, &de):
		return domain.NewTransient(err, de.RetryAfter)
	}
	return err
}

func (b backend) Status(context.Context) domain.WireStatus {
	now := b.clock.Now()
	st := domain.WireStatus{State: domain.StateValid, Providers: []domain.WireProviderStatus{}}
	for _, e := range b.c.Entries() {
		ps := domain.WireProviderStatus{Provider: e.Key.Provider, State: e.State, LastError: e.LastErrorClass()}
		if !e.Credential.Value.IsZero() {
			exp := e.Credential.ExpiresAt.UTC()
			ps.ExpiresAt = &exp
		}
		if e.State == domain.StateDegraded && e.NextRefresh.After(now) {
			ps.RetryAfter = int((e.NextRefresh.Sub(now) + time.Second - 1) / time.Second)
		}
		switch {
		case e.State == domain.StateRevoked:
			st.State = domain.StateRevoked
		case e.State == domain.StateDegraded && st.State != domain.StateRevoked:
			st.State = domain.StateDegraded
		}
		st.Providers = append(st.Providers, ps)
	}
	return st
}
