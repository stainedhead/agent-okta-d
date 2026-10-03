package cache

import (
	"context"
	"sync"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

func (c *Cache) newEvent(e *entry, t domain.AuditEventType, now time.Time) domain.AuditEvent {
	return domain.AuditEvent{TS: now, AgentID: c.cfg.AgentID, Event: t, Provider: e.key.Provider, Audience: e.key.Audience}
}

func (c *Cache) send(ev domain.AuditEvent) {
	if c.cfg.Audit != nil {
		c.cfg.Audit.Emit(c.base, ev)
	}
}

// emit sends an audit event (FR-11); cred and err are optional.
func (c *Cache) emit(e *entry, t domain.AuditEventType, now time.Time, cred domain.Credential, err error) {
	ev := c.newEvent(e, t, now)
	if !cred.Value.IsZero() {
		ev = ev.WithCredential(cred)
	}
	ev = ev.WithError(err)
	c.send(ev)
}

func (c *Cache) auditServe(ctx context.Context, e *entry, cred domain.Credential, now time.Time) {
	ev := c.newEvent(e, domain.AuditServe, now).WithCredential(cred)
	ev.Result = domain.ResultOK
	if ci, ok := ctx.Value(callerKey{}).(domain.CallerInfo); ok {
		ev = ev.WithCaller(ci)
	}
	c.send(ev)
}

// Poll runs everything that is due at the clock's current time and waits for
// it: refreshes at their scheduled time (also immediately after a suspend/wake,
// PRD risk 9), the first mint of empty entries, retries after backoff, and the
// degrade deadline. Run calls it from the scheduler loop; tests call it
// directly with a fake clock for deterministic stepping.
func (c *Cache) Poll(ctx context.Context) {
	now := c.cfg.Clock.Now()
	var due []*flight
	var toClean []*entry
	c.mu.Lock()
	for _, e := range c.entries {
		if e.fl != nil || e.state == domain.StateRevoked || e.state == domain.StateReauthRequired {
			continue
		}
		if e.state.Servable() && e.lastErr != nil && e.cred.Remaining(now) <= c.cfg.DegradeBefore {
			if c.degrade(e, e.lastErr) {
				toClean = append(toClean, e)
			}
		}
		if !e.nextRefresh.IsZero() && !now.Before(e.nextRefresh) {
			if f, err := c.startFlight(e, false); err == nil {
				due = append(due, f)
			}
		}
	}
	c.mu.Unlock()
	for _, e := range toClean {
		c.removeSinks(e)
	}
	for _, f := range due {
		_ = c.wait(ctx, f)
	}
}

// untilNext is how long until Poll has work; idle when nothing is scheduled.
func (c *Cache) untilNext() time.Duration {
	now := c.cfg.Clock.Now()
	next := now.Add(time.Hour)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.entries {
		if e.fl != nil || e.state == domain.StateRevoked || e.state == domain.StateReauthRequired {
			continue
		}
		if !e.nextRefresh.IsZero() && e.nextRefresh.Before(next) {
			next = e.nextRefresh
		}
		if e.state.Servable() && e.lastErr != nil {
			if dl := e.cred.ExpiresAt.Add(-c.cfg.DegradeBefore); dl.Before(next) {
				next = dl
			}
		}
	}
	return max(next.Sub(now), 0)
}

// Run is the scheduler loop. It returns when ctx is done or the daemon is
// revoked. Mints are started from a context owned by the Cache, so cancelling
// ctx never aborts a half-finished credential write; call Close to do that.
func (c *Cache) Run(ctx context.Context) {
	for {
		t := c.cfg.Clock.NewTimer(c.untilNext())
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-c.revoked:
			t.Stop()
			return
		case <-c.wake:
			t.Stop()
		case <-t.C():
		}
		c.Poll(ctx)
	}
}

// Revoke is the manual revoke entry point (`revoke` subcommand, signal
// handler): every entry becomes revoked, sinks are removed, provider Revoke
// hooks run best effort and Revoked() is closed. The caller completes the
// remaining steps of the withdraw sequence (PRD 13) and exits 77.
func (c *Cache) Revoke(ctx context.Context) {
	c.revokeAll(ctx, "manual")
}

type withdraw struct {
	e    *entry
	cred domain.Credential
}

func (c *Cache) revokeAll(ctx context.Context, reason string) {
	c.mu.Lock()
	ws := c.revokeLocked(c.cfg.Clock.Now(), reason)
	c.mu.Unlock()
	c.withdrawAll(ctx, ws)
}

// revokeLocked moves every entry to revoked and drops its credential. Caller
// holds mu. It returns what withdrawAll still has to clean up outside the lock.
func (c *Cache) revokeLocked(now time.Time, reason string) []withdraw {
	var ws []withdraw
	for _, e := range c.entries {
		if e.state == domain.StateRevoked {
			continue
		}
		ws = append(ws, withdraw{e, e.cred})
		e.cred, e.nextRefresh, e.lastErr = domain.Credential{}, time.Time{}, domain.ErrRevoked
		c.setState(e, domain.StateRevoked, domain.ErrRevoked)
		ev := c.newEvent(e, domain.AuditRevoke, now)
		ev.Result, ev.Detail = domain.ResultOK, reason
		c.send(ev)
	}
	return ws
}

// withdrawAll removes sinks and runs the provider hooks, then closes Revoked().
func (c *Cache) withdrawAll(ctx context.Context, ws []withdraw) {
	var wg sync.WaitGroup
	for _, w := range ws {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.removeSinks(w.e)
			// ASSUMPTION(A-04): a revocation call for client-credential tokens
			// may not exist; the hook is best effort and its error is ignored.
			if !w.cred.Value.IsZero() {
				_ = w.e.prov.Revoke(ctx, w.cred)
			}
		}()
	}
	wg.Wait()
	c.revOnce.Do(func() { close(c.revoked) })
}
