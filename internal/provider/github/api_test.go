package github

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/domain/domaintest"
)

func newAPI(t *testing.T, h http.HandlerFunc) *API {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &API{Base: srv.URL, HTTP: srv.Client(), Now: func() time.Time { return domaintest.Epoch }}
}

func TestA05_UserReadsExpiryHeader(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" || r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("bad request %s %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		// ASSUMPTION(A-05): expiry header format.
		w.Header().Set("github-authentication-token-expiration", "2026-11-01 12:00:00 UTC")
		_, _ = w.Write([]byte(`{"id":4242,"login":"agent-x_acme"}`))
	})
	u, err := api.User(context.Background(), domain.NewSecret("tok"))
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != 4242 || u.Login != "agent-x_acme" || !u.TokenExpiry.Equal(time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("%+v", u)
	}
}

func TestUserNoHeaderNoExpiry(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"id":1,"login":"a"}`)) })
	u, err := api.User(context.Background(), domain.NewSecret("tok"))
	if err != nil || !u.TokenExpiry.IsZero() {
		t.Fatalf("%+v %v", u, err)
	}
}

func TestA05_ParseExpiryHeader(t *testing.T) {
	good := map[string]time.Time{
		"2026-11-01 12:00:00 UTC":   time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC),
		"2026-11-01 12:00:00 -0700": time.Date(2026, 11, 1, 19, 0, 0, 0, time.UTC),
		"2026-11-01T12:00:00Z":      time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC),
	}
	for in, want := range good {
		if got, ok := ParseExpiryHeader(in); !ok || !got.Equal(want) {
			t.Errorf("%q: %v %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "soon", "2026-13-99"} {
		if _, ok := ParseExpiryHeader(bad); ok {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestStatusClassification(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		headers map[string]string
		is      error
		retry   time.Duration
	}{
		{"401", 401, nil, domain.ErrReauthRequired, 0},
		{"429 retry-after", 429, map[string]string{"Retry-After": "30"}, domain.ErrTransient, 30 * time.Second},
		{"429 bare", 429, nil, domain.ErrTransient, 0},
		{"403 secondary", 403, map[string]string{"Retry-After": "60"}, domain.ErrTransient, 60 * time.Second},
		{"403 primary reset", 403, map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1790000000"}, domain.ErrTransient, 0},
		{"403 forbidden", 403, nil, domain.ErrProvider, 0},
		{"500", 500, nil, domain.ErrTransient, 0},
		{"503 retry date", 503, map[string]string{"Retry-After": domaintest.Epoch.Add(90 * time.Second).UTC().Format(http.TimeFormat)}, domain.ErrTransient, 90 * time.Second},
		{"404", 404, nil, domain.ErrProvider, 0},
	}
	for _, c := range cases {
		api := newAPI(t, func(w http.ResponseWriter, _ *http.Request) {
			for k, v := range c.headers {
				w.Header().Set(k, v)
			}
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(`{"message":"nope"}`))
		})
		_, err := api.User(context.Background(), domain.NewSecret("sekret"))
		if !errors.Is(err, c.is) {
			t.Errorf("%s: got %v want %v", c.name, err, c.is)
			continue
		}
		if strings.Contains(err.Error(), "sekret") {
			t.Errorf("%s: token leaked", c.name)
		}
		if c.retry > 0 {
			if d, ok := domain.RetryAfter(err); !ok || d != c.retry {
				t.Errorf("%s: retry %v %v want %v", c.name, d, ok, c.retry)
			}
		}
	}
}

func TestPrimaryRateLimitResetHint(t *testing.T) {
	reset := domaintest.Epoch.Add(5 * time.Minute).Unix()
	api := newAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset, 10))
		w.WriteHeader(403)
	})
	_, err := api.User(context.Background(), domain.NewSecret("t"))
	if d, ok := domain.RetryAfter(err); !ok || d != 5*time.Minute {
		t.Fatalf("%v %v %v", d, ok, err)
	}
}

func TestNetworkErrorIsTransient(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close()
	api := &API{Base: base, HTTP: http.DefaultClient}
	if _, err := api.User(context.Background(), domain.NewSecret("t")); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("got %v", err)
	}
}

func TestBadJSON(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`<html>`)) })
	if _, err := api.User(context.Background(), domain.NewSecret("t")); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("got %v", err)
	}
	api = newAPI(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"id":0,"login":""}`)) })
	if _, err := api.User(context.Background(), domain.NewSecret("t")); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("empty login: %v", err)
	}
}

func TestRepoRead(t *testing.T) {
	api := newAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/widgets" {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(`{"full_name":"acme/widgets"}`))
	})
	if err := api.Repo(context.Background(), domain.NewSecret("t"), "acme/widgets"); err != nil {
		t.Fatal(err)
	}
	if err := api.Repo(context.Background(), domain.NewSecret("t"), "acme/other"); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("got %v", err)
	}
}

// FR-R08: neither the API client nor the configured default follows redirects.
func TestAPIDoesNotFollowRedirect(t *testing.T) {
	var hits atomic.Int32
	second := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer second.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.URL+"/user", http.StatusTemporaryRedirect)
	}))
	defer first.Close()
	a := &API{Base: first.URL, HTTP: &http.Client{}}
	_, _ = a.User(context.Background(), domain.NewSecret("tok"))
	a.HTTP = nil
	_, _ = a.User(context.Background(), domain.NewSecret("tok"))
	if hits.Load() != 0 {
		t.Fatalf("redirect target received %d requests", hits.Load())
	}
	for _, hc := range []*http.Client{nil, {}} {
		c, err := (Config{APIBase: first.URL, Mode: ModePAT, Login: "x", StoreName: "s", SecretID: "i", HTTPClient: hc}).Normalize()
		if err != nil {
			t.Fatal(err)
		}
		if c.HTTPClient.CheckRedirect == nil {
			t.Fatal("normalized client follows redirects")
		}
	}
}
