package cache

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

type callerKey struct{}

// ContextWithCaller attaches the local caller so the serve audit event (FR-11)
// carries uid, pid and exe.
func ContextWithCaller(ctx context.Context, c domain.CallerInfo) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

type flight struct {
	done chan struct{}
	err  error
}

type entry struct {
	key         domain.Key
	prov        domain.Provider
	opts        Options
	cred        domain.Credential
	state       domain.State
	lastErr     error
	nextRefresh time.Time
	attempts    int       // consecutive failures, for backoff
	firstDef    time.Time // first definitive error awaiting confirmation
	fl          *flight
}

// Cache holds the entries. Create with New.
type Cache struct {
	cfg  Config
	base context.Context
	stop context.CancelFunc

	mu      sync.Mutex
	deps    domain.Deps
	entries []*entry // registration order
	revoked chan struct{}
	revOnce sync.Once
	wake    chan struct{}
}

// New builds a Cache. Invalid configuration is domain.ErrConfig.
func New(cfg Config) (*Cache, error) {
	if err := cfg.applyDefaults(); err != nil {
		return nil, err
	}
	base, stop := context.WithCancel(context.Background())
	return &Cache{cfg: cfg, base: base, stop: stop, deps: cfg.Deps, revoked: make(chan struct{}), wake: make(chan struct{}, 1)}, nil
}

// SetDeps supplies the Deps handed to providers (needed when Deps.Credential is
// backed by this cache, which makes construction circular).
func (c *Cache) SetDeps(d domain.Deps) {
	c.mu.Lock()
	c.deps = d
	c.mu.Unlock()
}

// Close cancels in-flight mints and stops Run. It does not revoke.
func (c *Cache) Close() { c.stop() }

// Revoked is closed once the daemon enters the revoked state, automatically or
// by Revoke. The app then finishes the withdraw sequence and exits 77.
func (c *Cache) Revoked() <-chan struct{} { return c.revoked }

// Register adds an entry in state empty. A duplicate key is domain.ErrConfig.
func (c *Cache) Register(p domain.Provider, key domain.Key, opts Options) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if key.Provider == "" {
		key.Provider = p.Name()
	}
	for _, e := range c.entries {
		if e.key == key {
			return domain.NewConfigError("cache.register", "duplicate key "+key.String())
		}
	}
	e := &entry{key: key, prov: p, opts: opts, state: domain.StateEmpty}
	e.nextRefresh = c.cfg.Clock.Now().Add(time.Duration(c.cfg.Rand() * float64(c.cfg.StartupJitter)))
	c.entries = append(c.entries, e)
	c.signal()
	return nil
}

func (c *Cache) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// find returns the first entry of a provider. Caller holds mu.
func (c *Cache) find(provider string) *entry {
	for _, e := range c.entries {
		if e.key.Provider == provider {
			return e
		}
	}
	return nil
}

func (c *Cache) findKey(k domain.Key) *entry {
	for _, e := range c.entries {
		if e.key == k {
			return e
		}
	}
	return nil
}

// Entry returns a snapshot of the first entry of provider.
func (c *Cache) Entry(provider string) (domain.CacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.find(provider)
	if e == nil {
		return domain.CacheEntry{}, false
	}
	return snapshot(e), true
}

// Entries returns snapshots of every entry ordered by key.
func (c *Cache) Entries() []domain.CacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]domain.CacheEntry, 0, len(c.entries))
	for _, e := range c.entries {
		out = append(out, snapshot(e))
	}
	slices.SortFunc(out, func(a, b domain.CacheEntry) int {
		switch {
		case a.Key.String() < b.Key.String():
			return -1
		case a.Key.String() > b.Key.String():
			return 1
		}
		return 0
	})
	return out
}

func snapshot(e *entry) domain.CacheEntry {
	return domain.CacheEntry{Key: e.key, Credential: e.cred, State: e.state, LastError: e.lastErr, NextRefresh: e.nextRefresh}
}

func (e *entry) fraction(c *Config) float64 {
	if e.opts.Fraction > 0 {
		return e.opts.Fraction
	}
	return c.Fraction
}

func (e *entry) jitter(c *Config) float64 {
	if e.opts.Jitter > 0 {
		return e.opts.Jitter
	}
	return c.Jitter
}

func (e *entry) margin(c *Config) time.Duration {
	if e.opts.MinMargin > 0 {
		return e.opts.MinMargin
	}
	return c.MinMargin
}

// Credential is the serve path: it returns the cached credential, refreshing
// synchronously when the entry is empty or less than MinTTL remains. It
// matches the signature of domain.Deps.Credential. Errors: domain.ErrRevoked,
// domain.ErrReauthRequired, *DegradedError, domain.ErrNotFound for an unknown
// provider, or the failed mint's error.
func (c *Cache) Credential(ctx context.Context, provider string) (domain.Credential, error) {
	c.mu.Lock()
	e := c.find(provider)
	c.mu.Unlock()
	if e == nil {
		return domain.Credential{}, fmt.Errorf("%w: provider %q", domain.ErrNotFound, provider)
	}
	return c.serve(ctx, e)
}

// CredentialFor is Credential addressed by the full cache key.
func (c *Cache) CredentialFor(ctx context.Context, k domain.Key) (domain.Credential, error) {
	c.mu.Lock()
	e := c.findKey(k)
	c.mu.Unlock()
	if e == nil {
		return domain.Credential{}, fmt.Errorf("%w: key %q", domain.ErrNotFound, k.String())
	}
	return c.serve(ctx, e)
}

func (c *Cache) serve(ctx context.Context, e *entry) (domain.Credential, error) {
	for range 3 {
		c.mu.Lock()
		now := c.cfg.Clock.Now()
		switch e.state {
		case domain.StateRevoked, domain.StateReauthRequired, domain.StateDegraded:
			err := c.stateErr(e, now)
			c.mu.Unlock()
			return domain.Credential{}, err
		case domain.StateValid, domain.StateRefreshing:
			if !e.cred.Expired(now) && e.cred.Remaining(now) >= e.opts.MinTTL {
				cred := e.cred
				c.auditServe(ctx, e, cred, now)
				c.mu.Unlock()
				return cred, nil
			}
		}
		// empty, minting, or servable but below MinTTL / expired: join or start a flight.
		f, err := c.startFlight(e, false)
		c.mu.Unlock()
		if err != nil {
			return domain.Credential{}, err
		}
		if err := c.wait(ctx, f); err != nil {
			return domain.Credential{}, c.flightErr(e, err)
		}
	}
	return domain.Credential{}, fmt.Errorf("provider %s: credential unstable: %w", e.key.Provider, domain.ErrTransient)
}

// flightErr maps a failed flight to the error the caller should see.
func (c *Cache) flightErr(e *entry, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		if c.base.Err() == nil {
			return err // the caller's own context
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e.state == domain.StateRevoked || e.state == domain.StateReauthRequired || e.state == domain.StateDegraded {
		return c.stateErr(e, c.cfg.Clock.Now())
	}
	// Still servable but the synchronous refresh failed (MinTTL case): answer
	// 503 with a retry hint rather than a credential below MinTTL.
	now := c.cfg.Clock.Now()
	return &DegradedError{Provider: e.key.Provider, RetryAfter: max(e.nextRefresh.Sub(now), c.cfg.BackoffMin), Cause: err}
}

// stateErr is the error for a non-servable state. Caller holds mu.
func (c *Cache) stateErr(e *entry, now time.Time) error {
	switch e.state {
	case domain.StateRevoked:
		return domain.ErrRevoked
	case domain.StateReauthRequired:
		return fmt.Errorf("%w: provider %s", domain.ErrReauthRequired, e.key.Provider)
	case domain.StateDegraded:
		ra := e.nextRefresh.Sub(now)
		return &DegradedError{Provider: e.key.Provider, RetryAfter: max(ra, c.cfg.BackoffMin), Cause: e.lastErr}
	}
	return nil
}

func (c *Cache) wait(ctx context.Context, f *flight) error {
	select {
	case <-f.done:
		return f.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Refresh forces a refresh (POST /v1/credentials/{provider}/refresh, and the
// call that leaves reauth_required after `enroll`). Concurrent callers share
// one mint.
func (c *Cache) Refresh(ctx context.Context, provider string) error {
	c.mu.Lock()
	e := c.find(provider)
	if e == nil {
		c.mu.Unlock()
		return fmt.Errorf("%w: provider %q", domain.ErrNotFound, provider)
	}
	f, err := c.startFlight(e, true)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if err := c.wait(ctx, f); err != nil {
		return c.flightErr(e, err)
	}
	return nil
}

// startFlight joins the entry's in-flight mint or starts one (single-flight,
// FR-3). Caller holds mu. forced allows leaving reauth_required.
func (c *Cache) startFlight(e *entry, forced bool) (*flight, error) {
	if e.state == domain.StateRevoked {
		return nil, domain.ErrRevoked
	}
	if e.fl != nil {
		return e.fl, nil
	}
	if e.state == domain.StateReauthRequired && !forced {
		return nil, c.stateErr(e, c.cfg.Clock.Now())
	}
	switch e.state {
	case domain.StateEmpty, domain.StateReauthRequired:
		c.setState(e, domain.StateMinting, nil)
	case domain.StateValid, domain.StateDegraded:
		c.setState(e, domain.StateRefreshing, nil)
	}
	f := &flight{done: make(chan struct{})}
	e.fl = f
	go c.run(e, f)
	return f, nil
}

func (c *Cache) run(e *entry, f *flight) {
	cred, err := c.mint(e)
	if err == nil {
		err = cred.Validate()
	}
	if err == nil && cred.Expired(c.cfg.Clock.Now()) {
		err = domain.Wrap(domain.ErrProvider, errors.New("credential already expired"))
	}
	var sinkErr error
	wrote := false
	if err == nil {
		wrote = true
		sinkErr = c.writeSinks(e.prov.Sinks(), cred)
	}
	c.finish(e, f, cred, err, sinkErr, wrote)
}

// mint calls the provider; a panic is converted to a provider error.
func (c *Cache) mint(e *entry) (cred domain.Credential, err error) {
	c.mu.Lock()
	deps := c.deps
	c.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			cred, err = domain.Credential{}, domain.NewProviderError(e.key.Provider, errors.New("mint panicked"))
		}
	}()
	return e.prov.Mint(c.base, deps)
}

func (c *Cache) writeSinks(specs []domain.SinkSpec, cred domain.Credential) error {
	if c.cfg.Sink == nil {
		return nil
	}
	var errs []error
	for _, s := range specs {
		if err := c.cfg.Sink.Write(c.base, s, cred.Value); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return domain.Wrap(domain.ErrProvider, errors.Join(errs...))
	}
	return nil
}

func (c *Cache) removeSinks(e *entry) {
	if c.cfg.Sink == nil {
		return
	}
	for _, s := range e.prov.Sinks() {
		_ = c.cfg.Sink.Remove(c.base, s) // best effort, missing file is not an error
	}
}

type actions struct {
	removeSinks bool
	revoke      bool
}

// finish records the outcome of a flight.
func (c *Cache) finish(e *entry, f *flight, cred domain.Credential, err, sinkErr error, wrote bool) {
	c.mu.Lock()
	now := c.cfg.Clock.Now()
	var act actions
	var ws []withdraw
	switch {
	case e.state == domain.StateRevoked: // revoked wins over a concurrent refresh
		f.err = domain.ErrRevoked
		act.removeSinks = wrote
	case err == nil:
		first := e.cred.Value.IsZero()
		e.cred, e.lastErr, e.attempts, e.firstDef = cred, sinkErr, 0, time.Time{}
		c.setState(e, domain.StateValid, nil)
		if sinkErr != nil {
			e.attempts++
			c.failedRetry(e, sinkErr, now, backoffDelay(e.attempts, c.cfg.BackoffMin, c.cfg.BackoffMax, c.cfg.Rand()))
			c.emit(e, domain.AuditFailure, now, domain.Credential{}, sinkErr)
		} else {
			e.nextRefresh = refreshAt(cred, e.fraction(&c.cfg), e.jitter(&c.cfg), e.margin(&c.cfg), c.cfg.Rand())
		}
		ev := domain.AuditRefresh
		if first {
			ev = domain.AuditMint
		}
		c.emit(e, ev, now, cred, nil)
	default:
		f.err = err
		act = c.handleFailure(e, err, now)
		if act.revoke {
			f.err = domain.Wrap(domain.ErrRevoked, err)
		}
	}
	e.fl = nil
	if act.revoke {
		ws = c.revokeLocked(now, "definitive_auth_error")
	}
	c.signal()
	c.mu.Unlock()
	if act.removeSinks {
		c.removeSinks(e)
	}
	if act.revoke {
		c.withdrawAll(c.base, ws)
	}
	// Waiters are released last, so they observe a completed revocation.
	close(f.done)
}

// handleFailure classifies err. Caller holds mu.
func (c *Cache) handleFailure(e *entry, err error, now time.Time) actions {
	var act actions
	c.emit(e, domain.AuditFailure, now, domain.Credential{}, err)
	switch {
	case errors.Is(err, domain.ErrRevoked):
		act.revoke = true
	case errors.Is(err, domain.ErrReauthRequired): // FR-17: never retried
		e.lastErr, e.cred, e.nextRefresh = err, domain.Credential{}, time.Time{}
		if c.setState(e, domain.StateReauthRequired, err) {
			act.removeSinks = true
		}
	case errors.Is(err, domain.ErrAuthDefinitive): // FR-6: confirmed twice within the window
		if !e.firstDef.IsZero() && now.Sub(e.firstDef) <= c.cfg.RevokeWindow {
			e.lastErr = err
			act.revoke = true
			break
		}
		e.firstDef = now
		act.removeSinks = c.failedRetry(e, err, now, c.cfg.BackoffMin)
	default: // transient and every other class: backoff, never revocation
		e.attempts++
		d := backoffDelay(e.attempts, c.cfg.BackoffMin, c.cfg.BackoffMax, c.cfg.Rand())
		if ra, ok := domain.RetryAfter(err); ok {
			d = max(d, ra)
		}
		act.removeSinks = c.failedRetry(e, err, now, d)
	}
	return act
}

// failedRetry schedules the next attempt and degrades the entry when it has
// nothing servable or is within DegradeBefore of expiry (FR-5). It reports
// whether the entry's sinks should be removed. Caller holds mu.
func (c *Cache) failedRetry(e *entry, err error, now time.Time, delay time.Duration) bool {
	e.lastErr = err
	e.nextRefresh = now.Add(delay)
	if e.cred.Value.IsZero() || e.cred.Remaining(now) <= c.cfg.DegradeBefore {
		return c.degrade(e, err)
	}
	return false
}

// degrade moves to degraded; reports whether it newly did so. Caller holds mu.
func (c *Cache) degrade(e *entry, err error) bool {
	if e.state == domain.StateDegraded {
		return false
	}
	return c.setState(e, domain.StateDegraded, err)
}

// setState applies a legal transition and audits it. Caller holds mu.
func (c *Cache) setState(e *entry, to domain.State, cause error) bool {
	from := e.state
	if from == to {
		return false
	}
	if !domain.CanTransition(from, to) {
		c.cfg.Log.Error("illegal cache transition", "provider", e.key.Provider, "from", from, "to", to)
		return false
	}
	e.state = to
	c.cfg.Log.Info("cache state", "provider", e.key.Provider, "from", from, "to", to, "error_class", domain.ErrorClass(cause))
	ev := c.newEvent(e, domain.AuditStateChange, c.cfg.Clock.Now())
	ev.Detail = string(from) + "->" + string(to)
	if cause != nil {
		ev = ev.WithError(cause)
	} else {
		ev.Result = domain.ResultOK
	}
	c.send(ev)
	return true
}
