package cache

import (
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// refreshAt computes when a credential should next be refreshed (FR-4): at
// fraction of its TTL, shifted by up to +-jitter (r in [0,1) selects the
// shift), but never later than margin before expiry. A margin larger than half
// the TTL is capped at half so a very short-lived credential is not refreshed
// the moment it is issued (local decision, see doc.go).
func refreshAt(c domain.Credential, fraction, jitter float64, margin time.Duration, r float64) time.Time {
	ttl := c.TTL()
	f := min(max(fraction+jitter*(2*r-1), 0), 1)
	target := c.IssuedAt.Add(time.Duration(float64(ttl) * f))
	latest := c.ExpiresAt.Add(-min(margin, ttl/2))
	if latest.Before(target) {
		return latest
	}
	return target
}

// backoffDelay is the exponential backoff for the n-th consecutive failure
// (FR-5): lo, 2*lo, 4*lo ... capped at hi, scaled by a jitter factor in
// [0.8, 1.2) chosen by r, then clamped to [lo, hi].
func backoffDelay(attempt int, lo, hi time.Duration, r float64) time.Duration {
	base := lo
	for i := 1; i < attempt && base < hi; i++ {
		base *= 2
	}
	d := time.Duration(float64(base) * (0.8 + 0.4*r))
	return min(max(d, lo), hi)
}
