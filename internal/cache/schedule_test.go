package cache

import (
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/domain/domaintest"
)

func credTTL(ttl time.Duration) domain.Credential {
	return domain.Credential{
		Kind: domain.KindBearer, Value: domain.NewSecret("x"),
		IssuedAt: domaintest.Epoch, ExpiresAt: domaintest.Epoch.Add(ttl),
	}
}

func TestRefreshAtFractionAndJitter(t *testing.T) {
	c := credTTL(time.Hour)
	if got := refreshAt(c, 0.5, 0.05, 2*time.Minute, 0.5); !got.Equal(domaintest.Epoch.Add(30 * time.Minute)) {
		t.Fatalf("mid jitter: %v", got)
	}
	if got := refreshAt(c, 0.5, 0.05, 2*time.Minute, 0); !got.Equal(domaintest.Epoch.Add(27 * time.Minute)) {
		t.Fatalf("low jitter: %v", got)
	}
	if got := refreshAt(c, 0.5, 0.05, 2*time.Minute, 1); !got.Equal(domaintest.Epoch.Add(33 * time.Minute)) {
		t.Fatalf("high jitter: %v", got)
	}
}

func TestRefreshAtNeverLaterThanMinMargin(t *testing.T) {
	c := credTTL(time.Hour)
	got := refreshAt(c, 0.99, 0, 10*time.Minute, 0.5)
	if want := domaintest.Epoch.Add(50 * time.Minute); !got.Equal(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestRefreshAtShortTTLCapsMarginToHalf(t *testing.T) {
	c := credTTL(time.Minute) // shorter than the 2 min margin
	got := refreshAt(c, 0.9, 0, 2*time.Minute, 0.5)
	if want := domaintest.Epoch.Add(30 * time.Second); !got.Equal(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestRefreshAtClampsFraction(t *testing.T) {
	c := credTTL(time.Hour)
	if got := refreshAt(c, 0.01, 0.5, 0, 0); got.Before(c.IssuedAt) {
		t.Fatalf("before issue: %v", got)
	}
	if got := refreshAt(c, 1, 0.5, 0, 1); got.After(c.ExpiresAt) {
		t.Fatalf("after expiry: %v", got)
	}
}

func TestBackoffGrowsAndCaps(t *testing.T) {
	min, max := time.Second, time.Minute
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60, 60}
	for i, w := range want {
		got := backoffDelay(i+1, min, max, 0.5) // r=0.5 -> factor 1.0
		if got != w*time.Second {
			t.Fatalf("attempt %d: got %v want %v", i+1, got, w*time.Second)
		}
	}
}

func TestBackoffJitterBoundsAndHugeAttempt(t *testing.T) {
	min, max := time.Second, time.Minute
	for _, r := range []float64{0, 0.25, 0.5, 0.75, 0.999} {
		for n := 0; n < 200; n++ {
			d := backoffDelay(n, min, max, r)
			if d < min || d > max {
				t.Fatalf("attempt %d r=%v out of [1s,60s]: %v", n, r, d)
			}
		}
	}
}
