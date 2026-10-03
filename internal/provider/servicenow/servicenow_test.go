package servicenow_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/domain/domaintest"
	"github.com/stainedhead/agent-okta-d/internal/provider/servicenow"
)

var _ domain.Provider = (*servicenow.Provider)(nil)

func newProv(t *testing.T, url string) *servicenow.Provider {
	t.Helper()
	p, err := servicenow.New(servicenow.Config{InstanceURL: url, AuthServer: "agents-snow", Scope: "snow.agent"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNewValidation(t *testing.T) {
	cases := map[string]servicenow.Config{
		"empty url":      {AuthServer: "a", Scope: "s"},
		"bad scheme":     {InstanceURL: "ftp://x.service-now.com", AuthServer: "a", Scope: "s"},
		"http non-local": {InstanceURL: "http://x.service-now.com", AuthServer: "a", Scope: "s"},
		"no host":        {InstanceURL: "https://", AuthServer: "a", Scope: "s"},
		"no auth server": {InstanceURL: "https://x.service-now.com", Scope: "s"},
		"no scope":       {InstanceURL: "https://x.service-now.com", AuthServer: "a"},
		"neg min ttl":    {InstanceURL: "https://x.service-now.com", AuthServer: "a", Scope: "s", MinTTL: -time.Second},
		"bad whoami":     {InstanceURL: "https://x.service-now.com", AuthServer: "a", Scope: "s", WhoamiPath: "api/x"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := servicenow.New(cfg); !errors.Is(err, domain.ErrConfig) {
				t.Fatalf("want ErrConfig, got %v", err)
			}
		})
	}
	p, err := servicenow.New(servicenow.Config{InstanceURL: "http://127.0.0.1:1234", AuthServer: "a", Scope: "s"})
	if err != nil || p.MinTTL() != 120*time.Second {
		t.Fatalf("loopback http + default min ttl: %v %v", err, p)
	}
}

func TestStaticSurface(t *testing.T) {
	p := newProv(t, "https://x.service-now.com")
	if p.Name() != "servicenow" {
		t.Fatal(p.Name())
	}
	if len(p.Sinks()) != 0 { // SN-2: never written to disk by default
		t.Fatal("servicenow must not declare sinks")
	}
	if err := p.Revoke(context.Background(), domain.Credential{}); err != nil {
		t.Fatal(err)
	}
}

func TestMintSN1(t *testing.T) {
	deps := domaintest.NewFakeDeps()
	okta := deps.OktaV.(*domaintest.FakeOkta)
	p := newProv(t, "https://x.service-now.com")
	c, err := p.Mint(context.Background(), deps)
	if err != nil {
		t.Fatal(err)
	}
	if got := okta.Requests; len(got) != 1 || got[0].AuthServer != "agents-snow" || got[0].Scope != "snow.agent" {
		t.Fatalf("okta request: %+v", got)
	}
	if c.Kind != domain.KindBearer || c.Value.Reveal() != "okta-fake-token" || c.Audience() != "api://agents-snow" ||
		c.Meta[domain.MetaScope] != "snow.agent" || c.Meta[domain.MetaJTI] != "jti-fake" || c.TTL() != time.Hour {
		t.Fatalf("credential: %+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

// ASSUMPTION(A-02): lifetime comes from the Okta response, never hardcoded.
func TestMintTTLFromResponseA02(t *testing.T) {
	deps := domaintest.NewFakeDeps()
	deps.OktaV = &domaintest.FakeOkta{Clock: deps.ClockV, TokenFn: func(_ context.Context, r domain.OktaTokenRequest) (domain.OktaToken, error) {
		now := deps.ClockV.Now()
		return domain.OktaToken{AccessToken: domain.NewSecret("t"), IssuedAt: now, ExpiresAt: now.Add(7 * time.Minute), Audience: "snow-agents", Scope: r.Scope}, nil
	}}
	c, err := newProv(t, "https://x.service-now.com").Mint(context.Background(), deps)
	if err != nil || c.TTL() != 7*time.Minute || c.Audience() != "snow-agents" {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestMintErrors(t *testing.T) {
	p := newProv(t, "https://x.service-now.com")
	boom := domain.Wrap(domain.ErrAuthDefinitive, errors.New("invalid_client"))
	deps := domaintest.NewFakeDeps()
	deps.OktaV = &domaintest.FakeOkta{TokenFn: func(context.Context, domain.OktaTokenRequest) (domain.OktaToken, error) {
		return domain.OktaToken{}, boom
	}}
	if _, err := p.Mint(context.Background(), deps); !errors.Is(err, domain.ErrAuthDefinitive) {
		t.Fatalf("okta error must pass through classified: %v", err)
	}
	// invalid token shapes are ErrProvider and never leak the value
	for name, tok := range map[string]domain.OktaToken{
		"empty":   {IssuedAt: domaintest.Epoch, ExpiresAt: domaintest.Epoch.Add(time.Hour)},
		"no exp":  {AccessToken: domain.NewSecret("sekrit"), IssuedAt: domaintest.Epoch},
		"expired": {AccessToken: domain.NewSecret("sekrit"), IssuedAt: domaintest.Epoch.Add(-2 * time.Hour), ExpiresAt: domaintest.Epoch.Add(-time.Hour)},
	} {
		t.Run(name, func(t *testing.T) {
			d := domaintest.NewFakeDeps()
			d.OktaV = &domaintest.FakeOkta{TokenFn: func(context.Context, domain.OktaTokenRequest) (domain.OktaToken, error) { return tok, nil }}
			_, err := p.Mint(context.Background(), d)
			if !errors.Is(err, domain.ErrProvider) || strings.Contains(err.Error(), "sekrit") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestNeedsRefreshSN3(t *testing.T) {
	p, _ := servicenow.New(servicenow.Config{InstanceURL: "https://x.service-now.com", AuthServer: "a", Scope: "s", MinTTL: 120 * time.Second})
	now := domaintest.Epoch
	c := domain.Credential{Kind: domain.KindBearer, Value: domain.NewSecret("t"), IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	if p.NeedsRefresh(c, now) {
		t.Fatal("10 min left must not refresh")
	}
	if p.NeedsRefresh(c, now.Add(10*time.Minute-120*time.Second)) {
		t.Fatal("exactly min_ttl left is still acceptable")
	}
	if !p.NeedsRefresh(c, now.Add(10*time.Minute-119*time.Second)) {
		t.Fatal("below min_ttl must refresh")
	}
	if !p.NeedsRefresh(domain.Credential{}, now) {
		t.Fatal("zero credential must refresh")
	}
}

func TestFreshSyncRefreshSN3(t *testing.T) {
	deps := domaintest.NewFakeDeps()
	clk := deps.ClockV.(*domaintest.FakeClock)
	okta := deps.OktaV.(*domaintest.FakeOkta)
	okta.TokenFn = func(_ context.Context, r domain.OktaTokenRequest) (domain.OktaToken, error) {
		now := clk.Now()
		return domain.OktaToken{AccessToken: domain.NewSecret("tok-" + now.Format("150405")), IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), Audience: "snow-agents", Scope: r.Scope}, nil
	}
	p := newProv(t, "https://x.service-now.com")
	ctx := context.Background()
	c1, err := p.Fresh(ctx, deps, domain.Credential{})
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(5 * time.Minute)
	c2, err := p.Fresh(ctx, deps, c1)
	if err != nil || !c2.Value.Equal(c1.Value) || len(okta.Requests) != 1 {
		t.Fatalf("plenty left, must reuse: %v reqs=%d", err, len(okta.Requests))
	}
	clk.Advance(4*time.Minute + 30*time.Second) // 30 s left < 120 s
	c3, err := p.Fresh(ctx, deps, c2)
	if err != nil || c3.Value.Equal(c2.Value) || len(okta.Requests) != 2 || c3.Remaining(clk.Now()) < p.MinTTL() {
		t.Fatalf("must refresh synchronously: %v reqs=%d", err, len(okta.Requests))
	}
	okta.TokenFn = func(context.Context, domain.OktaTokenRequest) (domain.OktaToken, error) {
		return domain.OktaToken{}, domain.NewTransient(errors.New("down"), 0)
	}
	clk.Advance(9 * time.Minute)
	if _, err := p.Fresh(ctx, deps, c3); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("refresh failure must surface, not serve a short credential: %v", err)
	}
}

func cred(tok string) domain.Credential {
	return domain.Credential{Kind: domain.KindBearer, Value: domain.NewSecret(tok), IssuedAt: domaintest.Epoch, ExpiresAt: domaintest.Epoch.Add(time.Hour)}
}

// fakeSN is a ServiceNow fake: active tokens map to an active sys_user.
type fakeSN struct {
	*httptest.Server
	userActive atomic.Bool
	hits       atomic.Int32
	lastAuth   atomic.Value
	lastPath   atomic.Value
	status     atomic.Int32 // override when non-zero
	retryAfter string
}

func newFakeSN(t *testing.T) *fakeSN {
	f := &fakeSN{}
	f.userActive.Store(true)
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		f.lastAuth.Store(r.Header.Get("Authorization"))
		f.lastPath.Store(r.URL.RequestURI())
		if s := int(f.status.Load()); s != 0 {
			if f.retryAfter != "" {
				w.Header().Set("Retry-After", f.retryAfter)
			}
			w.WriteHeader(s)
			return
		}
		if r.Header.Get("Authorization") != "Bearer good" || !f.userActive.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"message":"User Not Authenticated"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"result":{"user_name":"agent"}}`))
	}))
	t.Cleanup(f.Close)
	return f
}

func TestProbeSN4(t *testing.T) {
	f := newFakeSN(t)
	p := newProv(t, f.URL)
	if err := p.Probe(context.Background(), cred("good")); err != nil {
		t.Fatal(err)
	}
	if f.lastAuth.Load() != "Bearer good" || f.lastPath.Load() != servicenow.DefaultWhoamiPath {
		t.Fatalf("auth=%v path=%v", f.lastAuth.Load(), f.lastPath.Load())
	}
}

func TestProbeCustomPath(t *testing.T) {
	f := newFakeSN(t)
	p, err := servicenow.New(servicenow.Config{InstanceURL: f.URL + "/", AuthServer: "a", Scope: "s", WhoamiPath: "/api/x_snow/whoami?v=1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Probe(context.Background(), cred("good")); err != nil {
		t.Fatal(err)
	}
	if f.lastPath.Load() != "/api/x_snow/whoami?v=1" {
		t.Fatal(f.lastPath.Load())
	}
}

func TestProbeDisabledUser(t *testing.T) {
	f := newFakeSN(t)
	p := newProv(t, f.URL)
	f.userActive.Store(false) // sys_user deactivated: Okta token still valid, instance rejects
	err := p.Probe(context.Background(), cred("good"))
	if !errors.Is(err, domain.ErrProvider) || !errors.Is(err, servicenow.ErrRejected) {
		t.Fatalf("want ErrProvider+ErrRejected, got %v", err)
	}
	if errors.Is(err, domain.ErrTransient) || errors.Is(err, domain.ErrAuthDefinitive) {
		t.Fatalf("must not look transient or an Okta rejection: %v", err)
	}
	if strings.Contains(err.Error(), "good") {
		t.Fatalf("leaks token: %v", err)
	}
	f.status.Store(403)
	if err := p.Probe(context.Background(), cred("good")); !errors.Is(err, servicenow.ErrRejected) {
		t.Fatalf("403: %v", err)
	}
}

func TestProbeStatusMapping(t *testing.T) {
	f := newFakeSN(t)
	p := newProv(t, f.URL)
	f.status.Store(503)
	f.retryAfter = "7"
	err := p.Probe(context.Background(), cred("good"))
	if ra, ok := domain.RetryAfter(err); !errors.Is(err, domain.ErrTransient) || !ok || ra != 7*time.Second {
		t.Fatalf("503: %v %v", err, ra)
	}
	f.status.Store(429)
	f.retryAfter = "bogus"
	if err := p.Probe(context.Background(), cred("good")); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("429: %v", err)
	}
	f.status.Store(404)
	if err := p.Probe(context.Background(), cred("good")); !errors.Is(err, domain.ErrProvider) || errors.Is(err, servicenow.ErrRejected) {
		t.Fatalf("404: %v", err)
	}
}

func TestProbeNetworkAndInputs(t *testing.T) {
	f := newFakeSN(t)
	p := newProv(t, f.URL)
	f.Close()
	if err := p.Probe(context.Background(), cred("good")); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("closed server: %v", err)
	}
	if err := p.Probe(context.Background(), domain.Credential{}); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("empty credential: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Probe(ctx, cred("good")); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("canceled: %v", err)
	}
}

func TestProbeDoesNotLeakTokenInTransportError(t *testing.T) {
	p := newProv(t, "http://127.0.0.1:1")
	err := p.Probe(context.Background(), cred("super-secret-token"))
	if err == nil || strings.Contains(err.Error(), "super-secret-token") {
		t.Fatalf("%v", err)
	}
}

// FR-R08: a 307 from the instance must not be followed (the bearer token
// would be re-sent to the second host).
func TestProbeDoesNotFollowRedirect(t *testing.T) {
	var hits atomic.Int32
	second := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer second.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.URL+"/x", http.StatusTemporaryRedirect)
	}))
	defer first.Close()
	p, err := servicenow.New(servicenow.Config{InstanceURL: first.URL, AuthServer: "a", Scope: "s", HTTPClient: &http.Client{}})
	if err != nil {
		t.Fatal(err)
	}
	_ = p.Probe(context.Background(), cred("good"))
	if hits.Load() != 0 {
		t.Fatalf("redirect target received %d requests", hits.Load())
	}
}
