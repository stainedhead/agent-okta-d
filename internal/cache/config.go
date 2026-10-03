package cache

import (
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// Defaults (PRD FR-4, FR-5, FR-6 and the section 10 refresh block).
const (
	DefaultFraction      = 0.5
	DefaultJitter        = 0.05
	DefaultMinMargin     = 120 * time.Second
	DefaultBackoffMin    = time.Second
	DefaultBackoffMax    = time.Minute
	DefaultDegradeBefore = 30 * time.Second
	DefaultRevokeWindow  = 30 * time.Second
)

// Config configures a Cache. Zero values take the defaults above.
type Config struct {
	Clock domain.Clock // required
	Deps  domain.Deps  // passed to Provider.Mint; may be set later with SetDeps
	Sink  domain.Sink  // optional; nil means providers' sinks are not written
	Audit domain.AuditSink
	Log   *slog.Logger

	AgentID string // audit agent_id

	Fraction  float64       // refresh at this fraction of TTL (default 0.5)
	Jitter    float64       // +- jitter on the fraction (default 0.05)
	MinMargin time.Duration // refresh no later than this before expiry (default 120 s)

	BackoffMin    time.Duration // default 1 s
	BackoffMax    time.Duration // default 60 s
	DegradeBefore time.Duration // degraded this long before expiry while failing (default 30 s)
	RevokeWindow  time.Duration // two definitive errors within this revoke (default 30 s)

	// StartupJitter spreads the first mint of each entry over [0, StartupJitter)
	// (PRD 7.1 suggests 0-30 s). Zero mints at the first poll.
	StartupJitter time.Duration

	// Rand returns a value in [0,1); default math/rand/v2.Float64. Tests inject it.
	Rand func() float64
}

// Options are per-entry overrides; zero values inherit from Config.
type Options struct {
	Fraction  float64
	Jitter    float64
	MinMargin time.Duration
	// MinTTL makes Credential refresh synchronously when less than MinTTL
	// remains (ServiceNow SN-3, default 120 s there; zero disables).
	MinTTL time.Duration
}

func (c *Config) applyDefaults() error {
	if c.Clock == nil {
		return domain.NewConfigError("cache.clock", "required")
	}
	if c.Fraction < 0 || c.Fraction > 1 {
		return domain.NewConfigError("refresh.fraction", "must be within (0,1]")
	}
	if c.Jitter < 0 || c.Jitter > 0.5 {
		return domain.NewConfigError("refresh.jitter", "must be within [0,0.5]")
	}
	if c.MinMargin < 0 || c.BackoffMin < 0 || c.BackoffMax < 0 || c.DegradeBefore < 0 || c.RevokeWindow < 0 || c.StartupJitter < 0 {
		return domain.NewConfigError("cache", "durations must not be negative")
	}
	if c.Fraction == 0 {
		c.Fraction = DefaultFraction
	}
	if c.Jitter == 0 {
		c.Jitter = DefaultJitter
	}
	if c.MinMargin == 0 {
		c.MinMargin = DefaultMinMargin
	}
	if c.BackoffMin == 0 {
		c.BackoffMin = DefaultBackoffMin
	}
	if c.BackoffMax == 0 {
		c.BackoffMax = DefaultBackoffMax
	}
	if c.BackoffMax < c.BackoffMin {
		return domain.NewConfigError("cache.backoff", "max below min")
	}
	if c.DegradeBefore == 0 {
		c.DegradeBefore = DefaultDegradeBefore
	}
	if c.RevokeWindow == 0 {
		c.RevokeWindow = DefaultRevokeWindow
	}
	if c.Log == nil {
		c.Log = slog.New(slog.DiscardHandler)
	}
	if c.Rand == nil {
		c.Rand = rand.Float64
	}
	return nil
}
