package msgraph

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/domain/domaintest"
)

const secretID = "agents/a1/msgraph"

type fakeEntra struct {
	mu       sync.Mutex
	status   int
	body     string
	header   http.Header
	forms    []url.Values
	graph    map[string]int // path -> status
	graphRaw map[string]string
	auth     []string
}

func (f *fakeEntra) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/tenant-1/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		f.forms = append(f.forms, r.PostForm)
		for k, v := range f.header {
			w.Header()[k] = v
		}
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(f.body))
	})
	mux.HandleFunc("/v1.0/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		p := r.URL.Path
		if r.URL.RawQuery != "" {
			p += "?" + r.URL.RawQuery
		}
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		st, ok := f.graph[p]
		if !ok {
			st = 200
		}
		w.WriteHeader(st)
		if raw, ok := f.graphRaw[p]; ok {
			_, _ = w.Write([]byte(raw))
		}
	})
	return mux
}

type env struct {
	e     *fakeEntra
	srv   *httptest.Server
	deps  *domaintest.FakeDeps
	store *domaintest.FakeStore
	p     *Provider
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &fakeEntra{status: 200, graph: map[string]int{}, graphRaw: map[string]string{
		"/v1.0/me": `{"userPrincipalName":"Agent@Example.com"}`,
	}}
	srv := httptest.NewServer(e.handler())
	t.Cleanup(srv.Close)
	d := domaintest.NewFakeDeps()
	st := &domaintest.FakeStore{}
	d.Stores["tokens"] = st
	if _, err := st.Put(context.Background(), secretID, domain.NewSecret("rt-old"), ""); err != nil {
		t.Fatal(err)
	}
	e.graph["/v1.0/users/other@example.com/messages"] = 403
	p, err := New(Config{
		TenantID: "tenant-1", ClientID: "client-1", UPN: "agent@example.com",
		Scopes: []string{"User.Read", "offline_access", "Mail.ReadWrite"}, StoreName: "tokens", SecretID: secretID,
		ProbeOtherUser: "other@example.com", LoginBase: srv.URL, GraphBase: srv.URL + "/v1.0", HTTP: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &env{e: e, srv: srv, deps: d, store: st, p: p}
}

func okBody(rt string) string {
	if rt == "" {
		return `{"token_type":"Bearer","access_token":"at-1","expires_in":3600,"scope":"User.Read Mail.ReadWrite"}`
	}
	return fmt.Sprintf(`{"token_type":"Bearer","access_token":"at-1","refresh_token":%q,"expires_in":3600}`, rt)
}

func TestMintRefreshGrantAndCredentialShape(t *testing.T) {
	v := newEnv(t)
	v.e.body = okBody("")
	c, err := v.p.Mint(context.Background(), v.deps)
	if err != nil {
		t.Fatal(err)
	}
	f := v.e.forms[0]
	if f.Get("grant_type") != "refresh_token" || f.Get("client_id") != "client-1" || f.Get("refresh_token") != "rt-old" ||
		f.Get("scope") != "User.Read offline_access Mail.ReadWrite" {
		t.Fatalf("bad form %v", f)
	}
	if c.Kind != domain.KindBearer || c.Value.Reveal() != "at-1" || c.Validate() != nil {
		t.Fatalf("bad cred %#v", c)
	}
	if c.TTL() != time.Hour || c.IssuedAt != v.deps.Clock().Now() {
		t.Fatalf("ttl %v issued %v", c.TTL(), c.IssuedAt)
	}
	if c.Audience() != "https://graph.microsoft.com" || c.Meta[domain.MetaScope] == "" {
		t.Fatalf("meta %v", c.Meta)
	}
	if v.store.Puts != 1 { // only the seed
		t.Fatalf("no rotation must not write, puts=%d", v.store.Puts)
	}
	if v.p.Name() != "msgraph" || len(v.p.Sinks()) != 0 || v.p.Revoke(context.Background(), c) != nil {
		t.Fatal("name/sinks/revoke")
	}
}

func TestMintPersistsRotatedRefreshTokenBeforeReturning(t *testing.T) {
	v := newEnv(t)
	v.e.body = okBody("rt-new")
	c, err := v.p.Mint(context.Background(), v.deps)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := v.store.Get(context.Background(), secretID)
	if got.Value.Reveal() != "rt-new" || c.Value.Reveal() != "at-1" {
		t.Fatalf("store=%q", got.Value.Reveal())
	}
	// Next mint uses the rotated token.
	if _, err := v.p.Mint(context.Background(), v.deps); err != nil {
		t.Fatal(err)
	}
	if v.e.forms[1].Get("refresh_token") != "rt-new" {
		t.Fatal("rotated token not used")
	}
}

func TestMintSameRefreshTokenIsNotRewritten(t *testing.T) {
	v := newEnv(t)
	v.e.body = okBody("rt-old")
	if _, err := v.p.Mint(context.Background(), v.deps); err != nil {
		t.Fatal(err)
	}
	if v.store.Puts != 1 {
		t.Fatalf("puts=%d", v.store.Puts)
	}
}

func TestMintPersistFailureWithholdsAccessToken(t *testing.T) {
	v := newEnv(t)
	v.e.body = okBody("rt-new")
	v.store.PutErr = errors.New("disk full")
	c, err := v.p.Mint(context.Background(), v.deps)
	if err == nil || !c.Value.IsZero() || !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("want provider error and no token, got %v %#v", err, c)
	}
	if strings.Contains(err.Error(), "rt-new") || strings.Contains(err.Error(), "at-1") {
		t.Fatal("secret leaked in error")
	}
}

func TestMintPersistVersionConflictIsTransient(t *testing.T) {
	v := newEnv(t)
	v.e.body = okBody("rt-new")
	v.store.PutErr = domain.ErrVersionConflict
	c, err := v.p.Mint(context.Background(), v.deps)
	if !errors.Is(err, domain.ErrTransient) || !c.Value.IsZero() {
		t.Fatalf("got %v", err)
	}
}

func TestMintErrorMapping(t *testing.T) {
	// ASSUMPTION(A-07): every invalid_grant variant maps to reauth_required.
	cases := []struct {
		name   string
		status int
		body   string
		hdr    http.Header
		want   error
		not    error
	}{
		{"A07_invalid_grant", 400, `{"error":"invalid_grant","error_description":"AADSTS50173: expired"}`, nil, domain.ErrReauthRequired, domain.ErrTransient},
		{"A07_invalid_grant_cae", 400, `{"error":"invalid_grant","error_description":"AADSTS50076 interaction"}`, nil, domain.ErrReauthRequired, nil},
		{"A07_interaction_required", 400, `{"error":"interaction_required"}`, nil, domain.ErrReauthRequired, nil},
		{"A07_consent_required", 400, `{"error":"consent_required"}`, nil, domain.ErrReauthRequired, nil},
		{"A07_invalid_grant_401", 401, `{"error":"invalid_grant"}`, nil, domain.ErrReauthRequired, nil},
		{"5xx", 503, `oops`, nil, domain.ErrTransient, domain.ErrReauthRequired},
		{"429", 429, `{}`, http.Header{"Retry-After": {"7"}}, domain.ErrTransient, nil},
		{"invalid_client", 401, `{"error":"invalid_client"}`, nil, domain.ErrConfig, domain.ErrReauthRequired},
		{"other4xx", 400, `{"error":"invalid_request"}`, nil, domain.ErrProvider, domain.ErrReauthRequired},
		{"garbage200", 200, `not json`, nil, domain.ErrProvider, nil},
		{"no_access_token", 200, `{"expires_in":3600}`, nil, domain.ErrProvider, nil},
		{"no_expiry", 200, `{"access_token":"x"}`, nil, domain.ErrProvider, nil},
		{"neg_expiry", 200, `{"access_token":"x","expires_in":-5}`, nil, domain.ErrProvider, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := newEnv(t)
			v.e.status, v.e.body, v.e.header = tc.status, tc.body, tc.hdr
			c, err := v.p.Mint(context.Background(), v.deps)
			if !errors.Is(err, tc.want) || (tc.not != nil && errors.Is(err, tc.not)) || !c.Value.IsZero() {
				t.Fatalf("got %v", err)
			}
			if tc.name == "429" {
				if d, ok := domain.RetryAfter(err); !ok || d != 7*time.Second {
					t.Fatalf("retry-after %v %v", d, ok)
				}
			}
			if errors.Is(err, domain.ErrAuthDefinitive) {
				t.Fatal("msgraph must never produce ErrAuthDefinitive (would revoke)")
			}
		})
	}
}

func TestMintNetworkErrorIsTransient(t *testing.T) {
	v := newEnv(t)
	v.srv.Close()
	_, err := v.p.Mint(context.Background(), v.deps)
	if !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("got %v", err)
	}
}

func TestMintStoreProblems(t *testing.T) {
	v := newEnv(t)
	empty := &domaintest.FakeStore{}
	v.deps.Stores["tokens"] = empty
	if _, err := v.p.Mint(context.Background(), v.deps); !errors.Is(err, domain.ErrReauthRequired) {
		t.Fatalf("not enrolled: %v", err)
	}
	delete(v.deps.Stores, "tokens")
	if _, err := v.p.Mint(context.Background(), v.deps); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("missing store: %v", err)
	}
	v.deps.Stores["tokens"] = &getErrStore{err: errors.New("boom")}
	if _, err := v.p.Mint(context.Background(), v.deps); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("store get err: %v", err)
	}
	blank := &domaintest.FakeStore{}
	_, _ = blank.Put(context.Background(), secretID, domain.NewSecret(""), "")
	v.deps.Stores["tokens"] = blank
	if _, err := v.p.Mint(context.Background(), v.deps); !errors.Is(err, domain.ErrReauthRequired) {
		t.Fatalf("blank token: %v", err)
	}
}

type getErrStore struct{ err error }

func (s *getErrStore) Get(context.Context, string) (domain.SecretValue, error) {
	return domain.SecretValue{}, s.err
}

func (s *getErrStore) Put(context.Context, string, domain.SecretString, string) (string, error) {
	return "", s.err
}

func TestNewValidatesConfig(t *testing.T) {
	good := Config{TenantID: "t", ClientID: "c", UPN: "u@x", Scopes: []string{"offline_access"}, StoreName: "s", SecretID: "k"}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Config){
		"tenant": func(c *Config) { c.TenantID = "" }, "client": func(c *Config) { c.ClientID = "" },
		"upn": func(c *Config) { c.UPN = "" }, "scopes": func(c *Config) { c.Scopes = nil },
		"store": func(c *Config) { c.StoreName = "" }, "secret": func(c *Config) { c.SecretID = "" },
		"no offline_access": func(c *Config) { c.Scopes = []string{"User.Read"} },
		"tenant slash":      func(c *Config) { c.TenantID = "a/b" },
	} {
		c := good
		mut(&c)
		if _, err := New(c); !errors.Is(err, domain.ErrConfig) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func cred() domain.Credential {
	return domain.Credential{Kind: domain.KindBearer, Value: domain.NewSecret("at-1")}
}

func TestProbeHappyPathIncludingNegativeCrossMailbox(t *testing.T) {
	v := newEnv(t)
	if err := v.p.Probe(context.Background(), cred()); err != nil {
		t.Fatal(err)
	}
	want := []string{"/v1.0/me", "/v1.0/me/mailFolders/inbox", "/v1.0/me/chats?$top=1", "/v1.0/users/other@example.com/messages"}
	if len(v.e.auth) != len(want) {
		t.Fatalf("calls %v", v.e.auth)
	}
	for _, a := range v.e.auth {
		if a != "Bearer at-1" {
			t.Fatalf("auth header %q", a)
		}
	}
}

func TestProbeCrossMailboxAllowedIsPolicyViolation(t *testing.T) {
	v := newEnv(t)
	v.e.graph["/v1.0/users/other@example.com/messages"] = 200
	err := v.p.Probe(context.Background(), cred())
	if !errors.Is(err, domain.ErrPolicy) {
		t.Fatalf("got %v", err)
	}
}

func TestProbeCrossMailboxOtherStatuses(t *testing.T) {
	v := newEnv(t)
	for st, want := range map[int]error{404: domain.ErrProvider, 401: domain.ErrProvider, 503: domain.ErrTransient} {
		v.e.graph["/v1.0/users/other@example.com/messages"] = st
		if err := v.p.Probe(context.Background(), cred()); !errors.Is(err, want) {
			t.Fatalf("%d: %v", st, err)
		}
	}
}

func TestProbePositiveFailures(t *testing.T) {
	for _, path := range []string{"/v1.0/me/mailFolders/inbox", "/v1.0/me/chats?$top=1"} {
		v := newEnv(t)
		v.e.graph[path] = 403
		if err := v.p.Probe(context.Background(), cred()); !errors.Is(err, domain.ErrProvider) {
			t.Fatalf("%s: %v", path, err)
		}
	}
	v := newEnv(t)
	v.e.graph["/v1.0/me/chats?$top=1"] = 429
	if err := v.p.Probe(context.Background(), cred()); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("429: %v", err)
	}
}

func TestProbeUPNMismatch(t *testing.T) {
	v := newEnv(t)
	v.e.graphRaw["/v1.0/me"] = `{"userPrincipalName":"someone-else@example.com"}`
	if err := v.p.Probe(context.Background(), cred()); !errors.Is(err, domain.ErrPolicy) {
		t.Fatalf("got %v", err)
	}
	v.e.graphRaw["/v1.0/me"] = `junk`
	if err := v.p.Probe(context.Background(), cred()); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("junk: %v", err)
	}
}

func TestProbeRequiresOtherUserAndToken(t *testing.T) {
	v := newEnv(t)
	cfg := v.p.cfg
	cfg.ProbeOtherUser = ""
	p, _ := New(cfg)
	if err := p.Probe(context.Background(), cred()); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("got %v", err)
	}
	if err := v.p.Probe(context.Background(), domain.Credential{}); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("empty cred: %v", err)
	}
	v.srv.Close()
	if err := v.p.Probe(context.Background(), cred()); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("net: %v", err)
	}
}

func TestNoSecretsInErrorsOrLogs(t *testing.T) {
	v := newEnv(t)
	v.e.status, v.e.body = 400, `{"error":"invalid_grant","error_description":"rt-old echoed"}`
	_, err := v.p.Mint(context.Background(), v.deps)
	if err == nil || strings.Contains(err.Error(), "rt-old") {
		t.Fatalf("refresh token leaked: %v", err)
	}
}

// FR-R08: a 307 on the token endpoint must not re-send the refresh token.
func TestMintDoesNotFollowRedirect(t *testing.T) {
	var hits atomic.Int32
	second := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer second.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.URL+"/tok", http.StatusTemporaryRedirect)
	}))
	defer first.Close()
	v := newEnv(t)
	cfg := v.p.cfg
	cfg.LoginBase, cfg.GraphBase, cfg.HTTP = first.URL, first.URL, &http.Client{}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Mint(context.Background(), v.deps); err == nil {
		t.Fatal("expected an error from the 307")
	}
	if hits.Load() != 0 {
		t.Fatalf("redirect target received %d requests", hits.Load())
	}
}
