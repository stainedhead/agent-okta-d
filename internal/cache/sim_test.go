package cache

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/domain/domaintest"
)

// TestSimulation24h steps a fake clock for 24 h in 1 s ticks with two providers
// (1 h and 10 min TTL), a short Okta outage and a long one, and checks the
// invariants of PRD M1: the credential served is never expired, the sink never
// holds an expired credential, the daemon never revokes on transient errors,
// every state change is a legal transition, and service resumes after each
// outage.
func TestSimulation24h(t *testing.T) {
	clk := domaintest.NewFakeClock()
	audit := &domaintest.RecordingAudit{}
	sink := &domaintest.FakeSink{}
	rng := rand.New(rand.NewPCG(7, 11))
	deps := domaintest.NewFakeDeps()
	deps.ClockV = clk

	var down atomic.Bool
	mk := func(name string, ttl time.Duration, path string) *domaintest.FakeProvider {
		p := &domaintest.FakeProvider{ProviderName: name, SinkSpecs: []domain.SinkSpec{{Path: path, Mode: 0o440}}}
		var n atomic.Int64
		p.MintFn = func(_ context.Context, d domain.Deps) (domain.Credential, error) {
			if down.Load() {
				return domain.Credential{}, domain.NewTransient(fmt.Errorf("okta 503"), 0)
			}
			now := d.Clock().Now()
			return domain.Credential{
				Kind: domain.KindBearer, Value: domain.NewSecret(fmt.Sprintf("%s-%d", name, n.Add(1))),
				IssuedAt: now, ExpiresAt: now.Add(ttl),
			}, nil
		}
		return p
	}
	aws, snow := mk("aws", time.Hour, "/aws.tok"), mk("snow", 10*time.Minute, "/snow.tok")

	c, err := New(Config{Clock: clk, Deps: deps, Sink: sink, Audit: audit, Rand: rng.Float64, StartupJitter: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Register(aws, domain.Key{Provider: "aws"}, Options{Fraction: 0.45}); err != nil {
		t.Fatal(err)
	}
	if err := c.Register(snow, domain.Key{Provider: "snow"}, Options{MinTTL: 120 * time.Second}); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	start := clk.Now()
	short := [2]time.Duration{3 * time.Hour, 3*time.Hour + 20*time.Minute}
	long := [2]time.Duration{14 * time.Hour, 14*time.Hour + 50*time.Minute}
	degradedSeen := map[string]bool{}
	servedAfterLong := map[string]bool{}
	const tick = time.Second

	for el := time.Duration(0); el < 24*time.Hour; el += tick {
		down.Store((el >= short[0] && el < short[1]) || (el >= long[0] && el < long[1]))
		c.Poll(ctx)
		if int(el/tick)%5 == 0 {
			for _, p := range []string{"aws", "snow"} {
				cred, err := c.Credential(ctx, p)
				switch {
				case err == nil:
					if cred.Expired(clk.Now()) {
						t.Fatalf("t=%v %s: served an expired credential", el, p)
					}
					if el >= long[1] {
						servedAfterLong[p] = true
					}
				case isDegraded(err):
					degradedSeen[p] = true
				default:
					t.Fatalf("t=%v %s: unexpected error %v", el, p, err)
				}
			}
		}
		// sink never holds an expired or stale credential
		for _, e := range c.Entries() {
			path := "/" + e.Key.Provider + ".tok"
			if v, ok := sink.Content(path); ok {
				if e.State == domain.StateDegraded || e.Credential.Expired(clk.Now()) || v != e.Credential.Value.Reveal() {
					t.Fatalf("t=%v %s: sink holds %q in state %s", el, e.Key.Provider, v, e.State)
				}
			}
		}
		select {
		case <-c.Revoked():
			t.Fatalf("t=%v: revoked on transient errors", el)
		default:
		}
		clk.Advance(tick)
	}

	if clk.Now().Sub(start) != 24*time.Hour {
		t.Fatal("clock")
	}
	for _, p := range []string{"aws", "snow"} {
		e, _ := c.Entry(p)
		if e.State != domain.StateValid {
			t.Errorf("%s final state %s", p, e.State)
		}
		if !servedAfterLong[p] {
			t.Errorf("%s did not resume after the long outage", p)
		}
	}
	if !degradedSeen["snow"] {
		t.Error("snow (10 min TTL) should have degraded during the 50 min outage")
	}
	if !degradedSeen["aws"] {
		t.Error("aws (1 h TTL) should have degraded during the 50 min outage")
	}
	// Refresh cadence: aws every ~27 min (24 h -> ~53 mints plus outage retries),
	// snow at 50 % of 10 min (~288 mints). Failed attempts count too, but
	// backoff is capped at 60 s so the totals stay bounded.
	if aws.Mints < 50 || aws.Mints > 53+3*60 {
		t.Errorf("aws mints %d", aws.Mints)
	}
	if snow.Mints < 280 || snow.Mints > 300+4*60 {
		t.Errorf("snow mints %d", snow.Mints)
	}
	// every audited state change is a legal transition and no event carries a secret
	for _, ev := range audit.Events() {
		if ev.Event == domain.AuditStateChange {
			from, to, _ := strings.Cut(ev.Detail, "->")
			if !domain.CanTransition(domain.State(from), domain.State(to)) {
				t.Fatalf("illegal transition %q", ev.Detail)
			}
		}
		if strings.Contains(fmt.Sprintf("%+v", ev), "aws-") || strings.Contains(fmt.Sprintf("%+v", ev), "snow-") {
			t.Fatalf("secret in audit event %+v", ev)
		}
	}
}

func isDegraded(err error) bool { return errors.Is(err, ErrDegraded) }
