package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/domain/domaintest"
)

type rig struct {
	t     *testing.T
	clk   *domaintest.FakeClock
	c     *Cache
	prov  *domaintest.FakeProvider
	sink  *domaintest.FakeSink
	audit *domaintest.RecordingAudit
	key   domain.Key

	nmints atomic.Int32
	mu     sync.Mutex
	script []func() (time.Duration, error) // per mint: ttl or error; nil => 1h ok
}

var sinkSpec = domain.SinkSpec{Path: "/run/agentd/aws.token", Mode: 0o440}

func newRig(t *testing.T, mut func(*Config)) *rig {
	t.Helper()
	r := &rig{t: t, clk: domaintest.NewFakeClock(), sink: &domaintest.FakeSink{}, audit: &domaintest.RecordingAudit{}}
	r.prov = &domaintest.FakeProvider{ProviderName: "aws", SinkSpecs: []domain.SinkSpec{sinkSpec}}
	r.prov.MintFn = r.mint
	cfg := Config{Clock: r.clk, Sink: r.sink, Audit: r.audit, Rand: func() float64 { return 0.5 }, AgentID: "agent-1"}
	deps := domaintest.NewFakeDeps()
	deps.ClockV = r.clk
	cfg.Deps = deps
	if mut != nil {
		mut(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	r.c = c
	r.key = domain.Key{Provider: "aws", Audience: "api://aws"}
	return r
}

func (r *rig) register(opts Options) {
	r.t.Helper()
	if err := r.c.Register(r.prov, r.key, opts); err != nil {
		r.t.Fatal(err)
	}
}

// next queues the outcome of the following mint.
func (r *rig) next(fs ...func() (time.Duration, error)) {
	r.mu.Lock()
	r.script = append(r.script, fs...)
	r.mu.Unlock()
}

func ok(ttl time.Duration) func() (time.Duration, error) {
	return func() (time.Duration, error) { return ttl, nil }
}
func fail(err error) func() (time.Duration, error) {
	return func() (time.Duration, error) { return 0, err }
}

var counter atomic.Int64

func (r *rig) mint(_ context.Context, d domain.Deps) (domain.Credential, error) {
	r.nmints.Add(1)
	r.mu.Lock()
	var f func() (time.Duration, error)
	if len(r.script) > 0 {
		f, r.script = r.script[0], r.script[1:]
	}
	r.mu.Unlock()
	ttl := time.Hour
	if f != nil {
		var err error
		if ttl, err = f(); err != nil {
			return domain.Credential{}, err
		}
	}
	now := d.Clock().Now()
	return domain.Credential{
		Kind: domain.KindBearer, Value: domain.NewSecret(fmt.Sprintf("tok-%d", counter.Add(1))),
		IssuedAt: now, ExpiresAt: now.Add(ttl),
		Meta: map[string]string{domain.MetaAudience: "api://aws", domain.MetaJTI: "j1"},
	}, nil
}

func (r *rig) state() domain.State {
	e, ok := r.c.Entry("aws")
	if !ok {
		r.t.Fatal("no entry")
	}
	return e.State
}

func (r *rig) events(t domain.AuditEventType) []domain.AuditEvent {
	var out []domain.AuditEvent
	for _, e := range r.audit.Events() {
		if e.Event == t {
			out = append(out, e)
		}
	}
	return out
}

var errNet = domain.NewTransient(errors.New("dial tcp: i/o timeout"), 0)
var errDef = domain.Wrap(domain.ErrAuthDefinitive, errors.New("invalid_client"))

func TestFirstServeMintsWritesSinkAndAudits(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	if r.state() != domain.StateEmpty {
		t.Fatal(r.state())
	}
	cred, err := r.c.Credential(context.Background(), "aws")
	if err != nil || cred.Value.Reveal() == "" {
		t.Fatalf("%v %v", cred, err)
	}
	if r.state() != domain.StateValid {
		t.Fatal(r.state())
	}
	if got, _ := r.sink.Content(sinkSpec.Path); got != cred.Value.Reveal() {
		t.Fatalf("sink %q", got)
	}
	if len(r.events(domain.AuditMint)) != 1 || len(r.events(domain.AuditServe)) != 1 {
		t.Fatalf("events %+v", r.audit.Events())
	}
	// Second call is served from cache with a serve event carrying the caller.
	ctx := ContextWithCaller(context.Background(), domain.CallerInfo{UID: 1001, PID: 42, Exe: "/usr/bin/aws"})
	if _, err := r.c.Credential(ctx, "aws"); err != nil {
		t.Fatal(err)
	}
	if r.prov.Mints != 1 {
		t.Fatalf("mints %d", r.prov.Mints)
	}
	s := r.events(domain.AuditServe)
	if len(s) != 2 || s[1].CallerUID == nil || *s[1].CallerUID != 1001 || s[1].CallerExe != "/usr/bin/aws" || s[1].AgentID != "agent-1" {
		t.Fatalf("serve %+v", s)
	}
}

func TestAuditNeverContainsSecret(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	cred, _ := r.c.Credential(context.Background(), "aws")
	for _, e := range r.audit.Events() {
		if s := fmt.Sprintf("%+v", e); contains(s, cred.Value.Reveal()) {
			t.Fatalf("secret in audit: %s", s)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestUnknownProviderAndDuplicateKey(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	if _, err := r.c.Credential(context.Background(), "nope"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := r.c.CredentialFor(context.Background(), domain.Key{Provider: "x"}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal(err)
	}
	if err := r.c.Refresh(context.Background(), "nope"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal(err)
	}
	if err := r.c.Register(r.prov, r.key, Options{}); !errors.Is(err, domain.ErrConfig) {
		t.Fatal(err)
	}
	if _, ok := r.c.Entry("nope"); ok {
		t.Fatal("entry")
	}
}

func TestCredentialForKey(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	if _, err := r.c.CredentialFor(context.Background(), r.key); err != nil {
		t.Fatal(err)
	}
}

func TestSingleFlightConcurrentCallers(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	gate := make(chan struct{})
	r.next(func() (time.Duration, error) { <-gate; return time.Hour, nil })
	var wg sync.WaitGroup
	creds := make([]string, 20)
	for i := range creds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := r.c.Credential(context.Background(), "aws")
			if err != nil {
				t.Error(err)
			}
			creds[i] = c.Value.Reveal()
		}()
	}
	// let all callers join the flight
	for deadline := time.Now().Add(2 * time.Second); r.state() != domain.StateMinting && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(gate)
	wg.Wait()
	if r.prov.Mints != 1 {
		t.Fatalf("mints = %d, want 1", r.prov.Mints)
	}
	for _, c := range creds {
		if c != creds[0] {
			t.Fatal("callers saw different credentials")
		}
	}
}

func TestCallerContextCancelDoesNotAbortFlight(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	gate := make(chan struct{})
	r.next(func() (time.Duration, error) { <-gate; return time.Hour, nil })
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { _, err := r.c.Credential(ctx, "aws"); errc <- err }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	close(gate)
	if _, err := r.c.Credential(context.Background(), "aws"); err != nil {
		t.Fatal(err)
	}
	if r.prov.Mints != 1 {
		t.Fatalf("mints %d", r.prov.Mints)
	}
}

func TestProactiveRefreshAtFraction(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	ctx := context.Background()
	if _, err := r.c.Credential(ctx, "aws"); err != nil {
		t.Fatal(err)
	}
	r.clk.Advance(29 * time.Minute)
	r.c.Poll(ctx)
	if r.prov.Mints != 1 || r.state() != domain.StateValid {
		t.Fatalf("early refresh: mints=%d state=%s", r.prov.Mints, r.state())
	}
	r.clk.Advance(time.Minute)
	r.c.Poll(ctx)
	if r.prov.Mints != 2 || r.state() != domain.StateValid {
		t.Fatalf("mints=%d state=%s", r.prov.Mints, r.state())
	}
	if len(r.events(domain.AuditRefresh)) != 1 {
		t.Fatalf("events %+v", r.audit.Events())
	}
	// state changes were audited: empty->minting, minting->valid, valid->refreshing, refreshing->valid
	var details []string
	for _, e := range r.events(domain.AuditStateChange) {
		details = append(details, e.Detail)
	}
	want := []string{"empty->minting", "minting->valid", "valid->refreshing", "refreshing->valid"}
	if fmt.Sprint(details) != fmt.Sprint(want) {
		t.Fatalf("transitions %v", details)
	}
}

func TestEntryOptionsOverrideFraction(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{Fraction: 0.45, Jitter: 0.01}) // AWS-2: refresh at <= 50 %
	if _, err := r.c.Credential(context.Background(), "aws"); err != nil {
		t.Fatal(err)
	}
	e, _ := r.c.Entry("aws")
	if want := domaintest.Epoch.Add(27 * time.Minute); !e.NextRefresh.Equal(want) {
		t.Fatalf("next %v want %v", e.NextRefresh, want)
	}
}

func TestMinTTLForcesSynchronousRefresh(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{MinTTL: 120 * time.Second})
	r.next(ok(5 * time.Minute))
	if _, err := r.c.Credential(context.Background(), "aws"); err != nil {
		t.Fatal(err)
	}
	r.clk.Advance(3*time.Minute + 30*time.Second) // 90 s left < min_ttl; scheduler has not run
	cred, err := r.c.Credential(context.Background(), "aws")
	if err != nil || r.prov.Mints != 2 || cred.Remaining(r.clk.Now()) < 120*time.Second {
		t.Fatalf("mints=%d rem=%v err=%v", r.prov.Mints, cred.Remaining(r.clk.Now()), err)
	}
}

func TestExpiredCredentialIsNeverServed(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	r.next(ok(10 * time.Minute))
	if _, err := r.c.Credential(context.Background(), "aws"); err != nil {
		t.Fatal(err)
	}
	r.clk.Advance(11 * time.Minute) // asleep past expiry, scheduler not run
	cred, err := r.c.Credential(context.Background(), "aws")
	if err != nil || cred.Expired(r.clk.Now()) {
		t.Fatalf("served expired: %v %v", cred.ExpiresAt, err)
	}
	if r.prov.Mints != 2 {
		t.Fatalf("mints %d", r.prov.Mints)
	}
}

func TestWakeFromSleepRefreshesImmediately(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	if _, err := r.c.Credential(context.Background(), "aws"); err != nil {
		t.Fatal(err)
	}
	r.clk.Advance(5 * time.Hour)
	r.c.Poll(context.Background())
	if r.prov.Mints != 2 || r.state() != domain.StateValid {
		t.Fatalf("mints=%d %s", r.prov.Mints, r.state())
	}
}

func TestTransientBackoffThenRecovery(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	ctx := context.Background()
	if _, err := r.c.Credential(ctx, "aws"); err != nil {
		t.Fatal(err)
	}
	r.clk.Advance(30 * time.Minute)
	r.next(fail(errNet), fail(errNet), fail(errNet))
	r.c.Poll(ctx) // fail 1 -> retry in 1 s
	e, _ := r.c.Entry("aws")
	if e.State != domain.StateRefreshing || e.NextRefresh.Sub(r.clk.Now()) != time.Second || e.LastError == nil {
		t.Fatalf("after 1: %s %v", e.State, e.NextRefresh.Sub(r.clk.Now()))
	}
	// still serves the old (valid) credential while refreshing
	if _, err := r.c.Credential(ctx, "aws"); err != nil {
		t.Fatal(err)
	}
	r.clk.Advance(time.Second)
	r.c.Poll(ctx) // fail 2 -> 2 s
	e, _ = r.c.Entry("aws")
	if e.NextRefresh.Sub(r.clk.Now()) != 2*time.Second {
		t.Fatalf("after 2: %v", e.NextRefresh.Sub(r.clk.Now()))
	}
	r.clk.Advance(2 * time.Second)
	r.c.Poll(ctx) // fail 3 -> 4 s
	e, _ = r.c.Entry("aws")
	if e.NextRefresh.Sub(r.clk.Now()) != 4*time.Second {
		t.Fatalf("after 3: %v", e.NextRefresh.Sub(r.clk.Now()))
	}
	r.clk.Advance(4 * time.Second)
	r.c.Poll(ctx) // success
	e, _ = r.c.Entry("aws")
	if e.State != domain.StateValid || e.LastError != nil {
		t.Fatalf("recovered: %s %v", e.State, e.LastError)
	}
	r.next(fail(errNet))
	r.clk.Advance(31 * time.Minute)
	r.c.Poll(ctx) // after success the backoff restarts at 1 s
	e, _ = r.c.Entry("aws")
	if e.NextRefresh.Sub(r.clk.Now()) != time.Second {
		t.Fatalf("backoff not reset: %v", e.NextRefresh.Sub(r.clk.Now()))
	}
}

func TestBackoffHonoursRetryAfterHint(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	r.next(fail(domain.NewTransient(errors.New("429"), 45*time.Second)))
	_, _ = r.c.Credential(context.Background(), "aws")
	e, _ := r.c.Entry("aws")
	if e.NextRefresh.Sub(r.clk.Now()) != 45*time.Second {
		t.Fatalf("retry-after not honoured: %v", e.NextRefresh.Sub(r.clk.Now()))
	}
}

func TestDegradedAtExpiryMinus30sAndRecovers(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	ctx := context.Background()
	r.next(ok(10 * time.Minute))
	if _, err := r.c.Credential(ctx, "aws"); err != nil {
		t.Fatal(err)
	}
	r.clk.Advance(5 * time.Minute) // refresh due; Okta is down from here on
	for range 50 {
		r.next(fail(errNet))
	}
	for r.clk.Now().Before(domaintest.Epoch.Add(10*time.Minute - 31*time.Second)) {
		r.c.Poll(ctx)
		if r.state() == domain.StateDegraded {
			t.Fatalf("degraded early at %v", r.clk.Now().Sub(domaintest.Epoch))
		}
		if _, err := r.c.Credential(ctx, "aws"); err != nil {
			t.Fatalf("not served at %v: %v", r.clk.Now().Sub(domaintest.Epoch), err)
		}
		r.clk.Advance(time.Second)
	}
	for r.clk.Now().Before(domaintest.Epoch.Add(10*time.Minute - 29*time.Second)) {
		r.clk.Advance(time.Second)
		r.c.Poll(ctx)
	}
	if r.state() != domain.StateDegraded {
		t.Fatalf("state %s", r.state())
	}
	_, err := r.c.Credential(ctx, "aws")
	var de *DegradedError
	if !errors.As(err, &de) || !errors.Is(err, ErrDegraded) || !errors.Is(err, domain.ErrTransient) || de.RetryAfter < time.Second {
		t.Fatalf("err %v", err)
	}
	if _, ok := r.sink.Content(sinkSpec.Path); ok {
		t.Fatal("sink should be removed while degraded")
	}
	// Okta comes back: degraded -> refreshing -> valid and the sink returns.
	r.mu.Lock()
	r.script = nil
	r.mu.Unlock()
	r.clk.Advance(time.Minute)
	r.c.Poll(ctx)
	if r.state() != domain.StateValid {
		t.Fatalf("state %s", r.state())
	}
	if _, ok := r.sink.Content(sinkSpec.Path); !ok {
		t.Fatal("sink not restored")
	}
	if _, err := r.c.Credential(ctx, "aws"); err != nil {
		t.Fatal(err)
	}
}

func TestPollDegradesWithoutAFlightAtDeadline(t *testing.T) {
	// A retry is scheduled far in the future (long Retry-After) so Poll must
	// degrade on the deadline by itself.
	r := newRig(t, nil)
	r.register(Options{})
	ctx := context.Background()
	r.next(ok(10 * time.Minute))
	_, _ = r.c.Credential(ctx, "aws")
	r.clk.Advance(5 * time.Minute)
	r.next(fail(domain.NewTransient(errors.New("429"), time.Hour)))
	r.c.Poll(ctx)
	if r.state() != domain.StateRefreshing {
		t.Fatal(r.state())
	}
	if d := r.c.untilNext(); d != 5*time.Minute-30*time.Second {
		t.Fatalf("untilNext %v", d)
	}
	r.clk.Advance(5*time.Minute - 30*time.Second)
	r.c.Poll(ctx)
	if r.state() != domain.StateDegraded {
		t.Fatal(r.state())
	}
}

func TestFirstMintTransientFailureIsDegraded(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	r.next(fail(errNet))
	_, err := r.c.Credential(context.Background(), "aws")
	if !errors.Is(err, ErrDegraded) || r.state() != domain.StateDegraded {
		t.Fatalf("%v %s", err, r.state())
	}
}

func TestDefinitiveErrorTwiceWithin30sRevokes(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	ctx := context.Background()
	if _, err := r.c.Credential(ctx, "aws"); err != nil {
		t.Fatal(err)
	}
	r.clk.Advance(30 * time.Minute)
	r.next(fail(errDef), fail(errDef))
	r.c.Poll(ctx)
	if r.state() != domain.StateRefreshing { // not revoked on the first one
		t.Fatalf("after first: %s", r.state())
	}
	select {
	case <-r.c.Revoked():
		t.Fatal("revoked early")
	default:
	}
	r.clk.Advance(time.Second)
	r.c.Poll(ctx)
	if r.state() != domain.StateRevoked {
		t.Fatalf("after second: %s", r.state())
	}
	select {
	case <-r.c.Revoked():
	default:
		t.Fatal("Revoked() not closed")
	}
	if _, err := r.c.Credential(ctx, "aws"); !errors.Is(err, domain.ErrRevoked) {
		t.Fatal(err)
	}
	if err := r.c.Refresh(ctx, "aws"); !errors.Is(err, domain.ErrRevoked) {
		t.Fatal(err)
	}
	if _, ok := r.sink.Content(sinkSpec.Path); ok {
		t.Fatal("sink left behind")
	}
	if r.prov.Revokes != 1 {
		t.Fatalf("revoke hooks %d", r.prov.Revokes)
	}
	if len(r.events(domain.AuditRevoke)) != 1 {
		t.Fatal("no revoke audit event")
	}
	e, _ := r.c.Entry("aws")
	if !e.Credential.Value.IsZero() || e.LastErrorClass() != "revoked" {
		t.Fatalf("credential kept: %+v", e)
	}
	r.clk.Advance(24 * time.Hour)
	r.c.Poll(ctx) // terminal: nothing happens
	if r.prov.Mints != 3 {
		t.Fatalf("mints %d", r.prov.Mints)
	}
}

func TestDefinitiveErrorsMoreThan30sApartDoNotRevoke(t *testing.T) {
	r := newRig(t, func(c *Config) { c.BackoffMin = time.Second })
	r.register(Options{})
	ctx := context.Background()
	r.next(fail(errDef))
	_, _ = r.c.Credential(ctx, "aws") // first definitive at t0
	r.clk.Advance(31 * time.Second)   // confirmation happens late
	r.next(fail(errDef), fail(errDef))
	r.c.Poll(ctx)
	if r.state() == domain.StateRevoked {
		t.Fatal("revoked although the errors were > 30 s apart")
	}
	r.clk.Advance(time.Second)
	r.c.Poll(ctx) // third failure, 1 s after the second: now confirmed
	if r.state() != domain.StateRevoked {
		t.Fatal(r.state())
	}
}

func TestSuccessBetweenDefinitiveErrorsResetsConfirmation(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	ctx := context.Background()
	r.next(fail(errDef), ok(time.Hour), fail(errDef))
	_, _ = r.c.Credential(ctx, "aws") // def #1
	r.clk.Advance(time.Second)
	r.c.Poll(ctx) // success
	r.clk.Advance(30 * time.Minute)
	r.c.Poll(ctx) // def again, but only once since the success
	if r.state() == domain.StateRevoked {
		t.Fatal("revoked on a single error after success")
	}
}

func TestTransientNeverRevokes(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	ctx := context.Background()
	for range 100 {
		r.next(fail(errNet))
	}
	for range 3000 {
		r.c.Poll(ctx)
		r.clk.Advance(time.Second)
	}
	if r.state() == domain.StateRevoked {
		t.Fatal("5xx/network treated as revocation")
	}
}

func TestOtherErrorClassesRetryWithoutRevocation(t *testing.T) {
	for _, err := range []error{
		domain.NewProviderError("aws", errors.New("bad")),
		domain.NewConfigError("x", "bad"),
		domain.Wrap(domain.ErrPolicy, errors.New("nope")),
		errors.New("who knows"),
	} {
		t.Run(domain.ErrorClass(err), func(t *testing.T) {
			r := newRig(t, nil)
			r.register(Options{})
			r.next(fail(err), fail(err))
			_, _ = r.c.Credential(context.Background(), "aws")
			r.clk.Advance(2 * time.Second)
			r.c.Poll(context.Background())
			if r.state() != domain.StateDegraded {
				t.Fatal(r.state())
			}
			e, _ := r.c.Entry("aws")
			if e.NextRefresh.Sub(r.clk.Now()) != 2*time.Second {
				t.Fatalf("backoff %v", e.NextRefresh.Sub(r.clk.Now()))
			}
		})
	}
}

func TestReauthRequiredIsNotRetriedAndIsolated(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	other := &domaintest.FakeProvider{ProviderName: "snow"}
	if err := r.c.Register(other, domain.Key{Provider: "snow"}, Options{}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	reauth := domain.Wrap(domain.ErrReauthRequired, errors.New("invalid_grant"))
	r.next(fail(reauth))
	_, err := r.c.Credential(ctx, "aws")
	if !errors.Is(err, domain.ErrReauthRequired) || r.state() != domain.StateReauthRequired {
		t.Fatalf("%v %s", err, r.state())
	}
	for range 100 {
		r.clk.Advance(time.Minute)
		r.c.Poll(ctx)
	}
	if r.prov.Mints != 1 {
		t.Fatalf("retry loop: %d mints", r.prov.Mints)
	}
	if _, err := r.c.Credential(ctx, "aws"); !errors.Is(err, domain.ErrReauthRequired) {
		t.Fatal(err)
	}
	// the other provider is unaffected and the daemon is not revoked
	if _, err := r.c.Credential(ctx, "snow"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.c.Revoked():
		t.Fatal("daemon revoked")
	default:
	}
	// after `enroll`, an explicit Refresh leaves reauth_required via minting
	if err := r.c.Refresh(ctx, "aws"); err != nil {
		t.Fatal(err)
	}
	if r.state() != domain.StateValid {
		t.Fatal(r.state())
	}
}

func TestReauthDuringRefreshDropsCredentialAndSink(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	ctx := context.Background()
	_, _ = r.c.Credential(ctx, "aws")
	r.clk.Advance(30 * time.Minute)
	r.next(fail(domain.Wrap(domain.ErrReauthRequired, errors.New("401"))))
	r.c.Poll(ctx)
	e, _ := r.c.Entry("aws")
	if e.State != domain.StateReauthRequired || !e.Credential.Value.IsZero() || e.LastErrorClass() != "reauth_required" {
		t.Fatalf("%+v", e)
	}
	if _, ok := r.sink.Content(sinkSpec.Path); ok {
		t.Fatal("sink kept")
	}
}

func TestInvalidCredentialFromProviderIsRejected(t *testing.T) {
	cases := map[string]func(now time.Time) domain.Credential{
		"empty value": func(now time.Time) domain.Credential {
			return domain.Credential{Kind: domain.KindBearer, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
		},
		"zero ttl": func(now time.Time) domain.Credential {
			return domain.Credential{Kind: domain.KindBearer, Value: domain.NewSecret("x"), IssuedAt: now, ExpiresAt: now}
		},
		"already expired": func(now time.Time) domain.Credential {
			return domain.Credential{Kind: domain.KindBearer, Value: domain.NewSecret("x"), IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, nil)
			r.prov.MintFn = func(_ context.Context, d domain.Deps) (domain.Credential, error) { return mk(d.Clock().Now()), nil }
			r.register(Options{})
			_, err := r.c.Credential(context.Background(), "aws")
			if !errors.Is(err, ErrDegraded) || !errors.Is(err, domain.ErrProvider) {
				t.Fatalf("err %v", err)
			}
			if _, ok := r.sink.Content(sinkSpec.Path); ok {
				t.Fatal("invalid credential reached the sink")
			}
		})
	}
}

func TestMintPanicBecomesProviderError(t *testing.T) {
	r := newRig(t, nil)
	r.prov.MintFn = func(context.Context, domain.Deps) (domain.Credential, error) { panic("boom token=abc") }
	r.register(Options{})
	_, err := r.c.Credential(context.Background(), "aws")
	if !errors.Is(err, domain.ErrProvider) || contains(err.Error(), "abc") {
		t.Fatalf("err %v", err)
	}
}

func TestSinkWriteFailureKeepsCredentialAndRetries(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	r.sink.WriteErr = errors.New("disk full")
	cred, err := r.c.Credential(context.Background(), "aws")
	if err != nil || cred.Value.IsZero() {
		t.Fatalf("%v", err)
	}
	e, _ := r.c.Entry("aws")
	if e.LastError == nil || e.NextRefresh.Sub(r.clk.Now()) != time.Second {
		t.Fatalf("no retry scheduled: %+v", e)
	}
	r.sink.WriteErr = nil
	r.clk.Advance(time.Second)
	r.c.Poll(context.Background())
	if _, ok := r.sink.Content(sinkSpec.Path); !ok {
		t.Fatal("sink not written after retry")
	}
}

func TestManualRevoke(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	ctx := context.Background()
	_, _ = r.c.Credential(ctx, "aws")
	r.c.Revoke(ctx)
	r.c.Revoke(ctx) // idempotent
	if r.state() != domain.StateRevoked || r.prov.Revokes != 1 {
		t.Fatalf("%s %d", r.state(), r.prov.Revokes)
	}
	if ev := r.events(domain.AuditRevoke); len(ev) != 1 || ev[0].Detail != "manual" {
		t.Fatalf("%+v", ev)
	}
}

func TestRevokeWinsOverConcurrentRefresh(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	gate := make(chan struct{})
	r.next(func() (time.Duration, error) { <-gate; return time.Hour, nil })
	errc := make(chan error, 1)
	go func() { _, err := r.c.Credential(context.Background(), "aws"); errc <- err }()
	for deadline := time.Now().Add(2 * time.Second); r.state() != domain.StateMinting && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	r.c.Revoke(context.Background())
	close(gate)
	if err := <-errc; !errors.Is(err, domain.ErrRevoked) {
		t.Fatalf("err %v", err)
	}
	if _, ok := r.sink.Content(sinkSpec.Path); ok {
		t.Fatal("sink resurrected after revoke")
	}
	e, _ := r.c.Entry("aws")
	if e.State != domain.StateRevoked || !e.Credential.Value.IsZero() {
		t.Fatalf("%+v", e)
	}
}

func TestProviderReportingRevokedRevokes(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	r.next(fail(domain.ErrRevoked))
	_, err := r.c.Credential(context.Background(), "aws")
	if !errors.Is(err, domain.ErrRevoked) || r.state() != domain.StateRevoked {
		t.Fatalf("%v %s", err, r.state())
	}
}

func TestRunLoopRefreshesOnFakeClock(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.c.Run(ctx); close(done) }()
	eventually(t, func() bool {
		return r.nmints.Load() == 1 && r.state() == domain.StateValid && r.clk.PendingTimers() > 0
	})
	for i := 2; i <= 4; i++ {
		r.clk.Advance(31 * time.Minute)
		eventually(t, func() bool {
			return int(r.nmints.Load()) >= i && r.state() == domain.StateValid && r.clk.PendingTimers() > 0
		})
	}
	cancel()
	<-done
}

func eventually(t *testing.T, f func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if f() {
			return
		}
	}
	t.Fatal("condition not reached")
}

func TestRunStopsOnRevoke(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	done := make(chan struct{})
	go func() { r.c.Run(context.Background()); close(done) }()
	eventually(t, func() bool { return r.state() == domain.StateValid })
	r.c.Revoke(context.Background())
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestRunWakesOnRegister(t *testing.T) {
	r := newRig(t, nil)
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { r.c.Run(ctx); close(done) }()
	eventually(t, func() bool { return r.clk.PendingTimers() == 1 })
	r.register(Options{})
	eventually(t, func() bool { return r.state() == domain.StateValid })
	cancel()
	<-done
}

func TestStartupJitterSpreadsFirstMint(t *testing.T) {
	r := newRig(t, func(c *Config) { c.StartupJitter = 30 * time.Second })
	r.register(Options{})
	r.c.Poll(context.Background())
	if r.state() != domain.StateEmpty {
		t.Fatalf("minted before jitter: %s", r.state())
	}
	r.clk.Advance(15 * time.Second)
	r.c.Poll(context.Background())
	if r.state() != domain.StateValid {
		t.Fatal(r.state())
	}
}

func TestSetDepsReachesProvider(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Deps = nil })
	var got domain.Deps
	r.prov.MintFn = func(ctx context.Context, d domain.Deps) (domain.Credential, error) {
		got = d
		return r.mint(ctx, d)
	}
	deps := domaintest.NewFakeDeps()
	deps.ClockV = r.clk
	r.c.SetDeps(deps)
	r.register(Options{})
	_, _ = r.c.Credential(context.Background(), "aws")
	if got != domain.Deps(deps) {
		t.Fatal("deps not passed")
	}
}

func TestNilSinkAndAuditAreAllowed(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Sink = nil; c.Audit = nil })
	r.register(Options{})
	if _, err := r.c.Credential(context.Background(), "aws"); err != nil {
		t.Fatal(err)
	}
	r.c.Revoke(context.Background())
}

func TestEntriesSorted(t *testing.T) {
	r := newRig(t, nil)
	_ = r.c.Register(&domaintest.FakeProvider{ProviderName: "zeta"}, domain.Key{Provider: "zeta"}, Options{})
	r.register(Options{})
	_ = r.c.Register(&domaintest.FakeProvider{ProviderName: "zeta2"}, domain.Key{Provider: "zeta"}, Options{})
	es := r.c.Entries()
	if len(es) != 2 || es[0].Key.Provider != "aws" {
		t.Fatalf("%+v", es)
	}
	_ = r.c.Register(&domaintest.FakeProvider{ProviderName: "b"}, domain.Key{}, Options{})
	if e, ok := r.c.Entry("b"); !ok || e.Key.Provider != "b" {
		t.Fatal("empty key provider not defaulted")
	}
}

func TestConfigValidation(t *testing.T) {
	clk := domaintest.NewFakeClock()
	bad := []Config{
		{},
		{Clock: clk, Fraction: 1.5},
		{Clock: clk, Fraction: -1},
		{Clock: clk, Jitter: 0.9},
		{Clock: clk, MinMargin: -1},
		{Clock: clk, BackoffMin: time.Minute, BackoffMax: time.Second},
	}
	for i, cfg := range bad {
		if _, err := New(cfg); !errors.Is(err, domain.ErrConfig) {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	c, err := New(Config{Clock: clk})
	if err != nil || c.cfg.Fraction != DefaultFraction || c.cfg.BackoffMax != time.Minute || c.cfg.DegradeBefore != 30*time.Second {
		t.Fatalf("defaults: %v", err)
	}
	c.Close()
}

func TestDegradedErrorText(t *testing.T) {
	e := &DegradedError{Provider: "aws"}
	if e.Error() == "" || e.Unwrap() != nil {
		t.Fatal("text")
	}
	e.Cause = errors.New("x")
	if e.Error() == "" || !errors.Is(e, e.Cause) {
		t.Fatal("cause")
	}
}

func TestMinTTLSyncRefreshFailureAnswersDegradedNotShortCredential(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{MinTTL: 120 * time.Second})
	r.next(ok(5 * time.Minute))
	_, _ = r.c.Credential(context.Background(), "aws")
	r.clk.Advance(3*time.Minute + 30*time.Second)
	r.next(fail(errNet))
	_, err := r.c.Credential(context.Background(), "aws")
	var de *DegradedError
	if !errors.As(err, &de) || de.RetryAfter < time.Second || !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("err %v", err)
	}
}

// FR-R02: two access_denied rejections on one provider (classified ErrProvider by
// internal/okta) leave the other providers valid; two invalid_client still
// revoke everything inside the window.
func TestPolicyDenialOnOneProviderLeavesOthersValid(t *testing.T) {
	r := newRig(t, nil)
	r.register(Options{})
	other := &domaintest.FakeProvider{ProviderName: "snow"}
	if err := r.c.Register(other, domain.Key{Provider: "snow"}, Options{}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := r.c.Credential(ctx, "snow"); err != nil {
		t.Fatal(err)
	}
	denied := domain.Wrap(domain.ErrProvider, errors.New("okta token request failed: access_denied (http 403)"))
	r.next(fail(denied), fail(denied))
	_, _ = r.c.Credential(ctx, "aws")
	r.clk.Advance(time.Second)
	r.c.Poll(ctx)
	select {
	case <-r.c.Revoked():
		t.Fatal("daemon revoked by a single provider's policy denial")
	default:
	}
	if e, _ := r.c.Entry("snow"); e.State == domain.StateRevoked {
		t.Fatalf("snow %s", e.State)
	}
	if _, err := r.c.Credential(ctx, "snow"); err != nil {
		t.Fatal(err)
	}
}
