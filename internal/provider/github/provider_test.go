package github

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
)

const testKey = "agents/x/github"

type fixture struct {
	p     *Provider
	deps  *domaintest.FakeDeps
	store *domaintest.FakeStore
	clk   *domaintest.FakeClock
	srv   *httptest.Server
	hits  atomic.Int32
}

func newFixture(t *testing.T, mutate func(*Config), h func(w http.ResponseWriter, r *http.Request)) *fixture {
	t.Helper()
	f := &fixture{store: &domaintest.FakeStore{}, deps: domaintest.NewFakeDeps()}
	f.clk = f.deps.ClockV.(*domaintest.FakeClock)
	f.deps.Stores["aws"] = f.store
	if h == nil {
		h = func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/user" {
				_, _ = w.Write([]byte(`{"id":7,"login":"agent-x_acme"}`))
				return
			}
			_, _ = w.Write([]byte(`{}`))
		}
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		h(w, r)
	}))
	t.Cleanup(f.srv.Close)
	cfg := Config{APIBase: f.srv.URL, Mode: ModePAT, Login: "agent-x_acme", StoreName: "aws", SecretID: testKey, HTTPClient: f.srv.Client()}
	if mutate != nil {
		mutate(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.p = p
	return f
}

func (f *fixture) put(t *testing.T, s Stored) {
	t.Helper()
	sec, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	cur, gerr := f.store.Get(context.Background(), testKey)
	ver := ""
	if gerr == nil {
		ver = cur.Version
	}
	if _, err := f.store.Put(context.Background(), testKey, sec, ver); err != nil {
		t.Fatal(err)
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("got %v", err)
	}
}

func TestIdentity(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.TokenFile = "/run/agentd/gh-token" }, nil)
	if f.p.Name() != "github" {
		t.Fatal(f.p.Name())
	}
	s := f.p.Sinks()
	if len(s) != 1 || s[0].Path != "/run/agentd/gh-token" || s[0].Mode != 0o440 {
		t.Fatalf("sinks %+v", s)
	}
	f2 := newFixture(t, nil, nil)
	if len(f2.p.Sinks()) != 0 {
		t.Fatal("no sink expected")
	}
	if err := f2.p.Revoke(context.Background(), domain.Credential{}); err != nil {
		t.Fatal(err)
	}
}

func TestMintStaticSecret(t *testing.T) {
	f := newFixture(t, nil, nil)
	f.put(t, Stored{Mode: ModePAT, Token: "ghp_abc", ExpiresAt: f.clk.Now().Add(90 * 24 * time.Hour)})
	c, err := f.p.Mint(context.Background(), f.deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Kind != domain.KindStaticSecret || c.Value.Reveal() != "ghp_abc" {
		t.Fatalf("%+v", c)
	}
	if c.TTL() != DefaultRefetchInterval {
		t.Fatalf("horizon %v", c.TTL())
	}
	if c.Meta[domain.MetaLogin] != "agent-x_acme" || c.Meta["mode"] != "pat" || c.Meta[MetaTokenExpiresAt] == "" {
		t.Fatalf("meta %v", c.Meta)
	}
	if f.hits.Load() != 0 {
		t.Fatal("mint must not touch the network")
	}
}

func TestMintHorizonCappedByTokenExpiry(t *testing.T) {
	f := newFixture(t, nil, nil)
	f.put(t, Stored{Token: "t", ExpiresAt: f.clk.Now().Add(5 * time.Minute)})
	c, err := f.p.Mint(context.Background(), f.deps)
	if err != nil || c.TTL() != 5*time.Minute {
		t.Fatalf("%v %v", c.TTL(), err)
	}
}

func TestMintNoKnownExpiry(t *testing.T) {
	f := newFixture(t, nil, nil)
	f.put(t, Stored{Token: "t"})
	c, err := f.p.Mint(context.Background(), f.deps)
	if err != nil || c.TTL() != DefaultRefetchInterval || c.Meta[MetaTokenExpiresAt] != "" {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestMintExpiredIsReauth(t *testing.T) {
	f := newFixture(t, nil, nil)
	f.put(t, Stored{Token: "t", ExpiresAt: f.clk.Now().Add(-time.Second)})
	_, err := f.p.Mint(context.Background(), f.deps)
	if !errors.Is(err, domain.ErrReauthRequired) {
		t.Fatalf("got %v", err)
	}
}

func TestMintStoreErrors(t *testing.T) {
	f := newFixture(t, nil, nil)
	// missing secret: operator has not enrolled -> reauth_required, not a retry loop.
	if _, err := f.p.Mint(context.Background(), f.deps); !errors.Is(err, domain.ErrReauthRequired) {
		t.Fatalf("missing: %v", err)
	}
	f.put(t, Stored{Token: "t"})
	f.deps.Stores = map[string]domain.SecretStore{}
	if _, err := f.p.Mint(context.Background(), f.deps); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("store: %v", err)
	}
	f.deps.Stores["aws"] = errStore{errors.New("boom")}
	if _, err := f.p.Mint(context.Background(), f.deps); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("get err: %v", err)
	}
	f.deps.Stores["aws"] = errStore{domain.NewTransient(errors.New("net"), time.Second)}
	if _, err := f.p.Mint(context.Background(), f.deps); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("transient passthrough: %v", err)
	}
}

type errStore struct{ err error }

func (e errStore) Get(context.Context, string) (domain.SecretValue, error) {
	return domain.SecretValue{}, e.err
}
func (e errStore) Put(context.Context, string, domain.SecretString, string) (string, error) {
	return "", e.err
}

func TestMintCorruptSecret(t *testing.T) {
	f := newFixture(t, nil, nil)
	if _, err := f.store.Put(context.Background(), testKey, domain.NewSecret("{bad"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Mint(context.Background(), f.deps); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("got %v", err)
	}
}

func TestMintModeMismatch(t *testing.T) {
	f := newFixture(t, nil, nil)
	f.put(t, Stored{Mode: ModeOAuthDevice, Token: "t"})
	if _, err := f.p.Mint(context.Background(), f.deps); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("got %v", err)
	}
}

func TestExpiryWarning(t *testing.T) {
	f := newFixture(t, nil, nil)
	f.put(t, Stored{Token: "t", ExpiresAt: f.clk.Now().Add(10 * 24 * time.Hour)})
	c, err := f.p.Mint(context.Background(), f.deps)
	if err != nil {
		t.Fatal(err)
	}
	st, rem := f.p.TokenExpiry(c, f.clk.Now())
	if st != ExpiryWarn || rem != 10*24*time.Hour {
		t.Fatalf("%v %v", st, rem)
	}
	msg, ok := f.p.ExpiryWarning(c, f.clk.Now())
	if !ok || !strings.Contains(msg, "10 days") || strings.Contains(msg, "t\n") {
		t.Fatalf("%q %v", msg, ok)
	}
	f.clk.Advance(11 * 24 * time.Hour)
	if st, _ := f.p.TokenExpiry(c, f.clk.Now()); st != ExpiryExpired {
		t.Fatalf("want expired, got %v", st)
	}
	if msg, ok := f.p.ExpiryWarning(c, f.clk.Now()); !ok || !strings.Contains(msg, "expired") {
		t.Fatalf("%q", msg)
	}
	// no expiry -> no warning
	f.put(t, Stored{Token: "t"})
	c2, _ := f.p.Mint(context.Background(), f.deps)
	if _, ok := f.p.ExpiryWarning(c2, f.clk.Now()); ok {
		t.Fatal("unexpected warning")
	}
}

func TestMintLogsWarningWithoutToken(t *testing.T) {
	f := newFixture(t, nil, nil)
	var buf strings.Builder
	f.deps.LoggerV = newTextLogger(&buf)
	f.put(t, Stored{Token: "ghp_topsecret", ExpiresAt: f.clk.Now().Add(2 * 24 * time.Hour)})
	if _, err := f.p.Mint(context.Background(), f.deps); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "expires soon") || strings.Contains(buf.String(), "ghp_topsecret") {
		t.Fatalf("log: %q", buf.String())
	}
}

func TestProbeOK(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.ProbeRepo = "acme/widgets" }, nil)
	f.put(t, Stored{Token: "t"})
	c, _ := f.p.Mint(context.Background(), f.deps)
	if err := f.p.Probe(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if f.hits.Load() != 2 {
		t.Fatalf("want /user and repo read, hits=%d", f.hits.Load())
	}
}

func TestProbeLoginMismatch(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.Login = "someone-else" }, nil)
	f.put(t, Stored{Token: "t"})
	c, _ := f.p.Mint(context.Background(), f.deps)
	err := f.p.Probe(context.Background(), c)
	if !errors.Is(err, domain.ErrProvider) || !strings.Contains(err.Error(), "someone-else") {
		t.Fatalf("got %v", err)
	}
}

func TestProbeLoginCaseInsensitive(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.Login = "AGENT-X_ACME" }, nil)
	f.put(t, Stored{Token: "t"})
	c, _ := f.p.Mint(context.Background(), f.deps)
	if err := f.p.Probe(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

func TestProbe401RefetchesOnceThenReauth(t *testing.T) {
	// GH-9: on 401 re-fetch the secret once, then reauth_required.
	f := newFixture(t, nil, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer good" {
			_, _ = w.Write([]byte(`{"id":7,"login":"agent-x_acme"}`))
			return
		}
		w.WriteHeader(401)
	})
	f.put(t, Stored{Token: "stale"})
	c, _ := f.p.Mint(context.Background(), f.deps)

	// Secret rotated in the store: refetch picks it up and succeeds.
	f.put(t, Stored{Token: "good"})
	if err := f.p.Probe(context.Background(), c); err != nil {
		t.Fatalf("rotated secret should recover: %v", err)
	}

	// Store unchanged and still rejected: exactly one retry-free reauth.
	f.put(t, Stored{Token: "stale"})
	c, _ = f.p.Mint(context.Background(), f.deps)
	f.hits.Store(0)
	err := f.p.Probe(context.Background(), c)
	if !errors.Is(err, domain.ErrReauthRequired) {
		t.Fatalf("got %v", err)
	}
	if f.hits.Load() != 1 {
		t.Fatalf("same token must not be retried, hits=%d", f.hits.Load())
	}

	// Rotated but the new secret is also rejected: one retry then reauth.
	f.put(t, Stored{Token: "also-bad"})
	f.hits.Store(0)
	err = f.p.Probe(context.Background(), c)
	if !errors.Is(err, domain.ErrReauthRequired) || f.hits.Load() != 2 {
		t.Fatalf("got %v hits=%d", err, f.hits.Load())
	}
}

func TestProbe401WithoutDepsIsReauth(t *testing.T) {
	f := newFixture(t, nil, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) })
	c := domain.Credential{Kind: domain.KindStaticSecret, Value: domain.NewSecret("x")}
	if err := f.p.Probe(context.Background(), c); !errors.Is(err, domain.ErrReauthRequired) {
		t.Fatalf("got %v", err)
	}
}

func TestProbeRateLimitSurfacesRetryAfter(t *testing.T) {
	f := newFixture(t, nil, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "42")
		w.WriteHeader(429)
	})
	f.put(t, Stored{Token: "t"})
	c, _ := f.p.Mint(context.Background(), f.deps)
	f.hits.Store(0)
	err := f.p.Probe(context.Background(), c)
	if d, ok := domain.RetryAfter(err); !ok || d != 42*time.Second {
		t.Fatalf("%v %v %v", d, ok, err)
	}
	if f.hits.Load() != 1 {
		t.Fatal("must not hammer")
	}
}

func TestProbeRepoFailure(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.ProbeRepo = "acme/widgets" }, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user" {
			_, _ = w.Write([]byte(`{"id":7,"login":"agent-x_acme"}`))
			return
		}
		w.WriteHeader(404)
	})
	c := domain.Credential{Kind: domain.KindStaticSecret, Value: domain.NewSecret("x")}
	if err := f.p.Probe(context.Background(), c); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("got %v", err)
	}
}

func TestA05_HeaderOptionalMintIgnoresIt(t *testing.T) {
	// ASSUMPTION(A-05): header is optional; Mint relies only on the stored value.
	f := newFixture(t, nil, nil)
	f.put(t, Stored{Token: "t"})
	if _, err := f.p.Mint(context.Background(), f.deps); err != nil {
		t.Fatal(err)
	}
}
