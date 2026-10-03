package msgraph

import (
	"bytes"
	"context"
	"errors"
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

type fake struct {
	mu        sync.Mutex
	dcStatus  int
	dcBody    string
	polls     []pollAns // consumed in order; last repeats
	pollForms []url.Values
	dcForm    url.Values
	meBody    string
	meAuth    string
}

type pollAns struct {
	status int
	body   string
}

func (f *fake) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/t1/oauth2/v2.0/devicecode", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.dcForm = r.PostForm
		f.mu.Unlock()
		w.WriteHeader(f.dcStatus)
		_, _ = w.Write([]byte(f.dcBody))
	})
	mux.HandleFunc("/t1/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		f.pollForms = append(f.pollForms, r.PostForm)
		a := f.polls[min(len(f.pollForms)-1, len(f.polls)-1)]
		w.WriteHeader(a.status)
		_, _ = w.Write([]byte(a.body))
	})
	mux.HandleFunc("/v1.0/me", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.meAuth = r.Header.Get("Authorization")
		f.mu.Unlock()
		_, _ = w.Write([]byte(f.meBody))
	})
	return mux
}

type env struct {
	f     *fake
	clk   *domaintest.FakeClock
	store *domaintest.FakeStore
	out   *bytes.Buffer
	cfg   Config
}

func newEnv(t *testing.T) *env {
	t.Helper()
	f := &fake{
		dcStatus: 200,
		dcBody:   `{"device_code":"DEV","user_code":"ABCD-1234","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":5}`,
		polls: []pollAns{
			{400, `{"error":"authorization_pending"}`},
			{200, `{"token_type":"Bearer","access_token":"at","refresh_token":"rt-1","expires_in":3600}`},
		},
		meBody: `{"userPrincipalName":"agent@example.com"}`,
	}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	e := &env{f: f, clk: domaintest.NewFakeClock(), store: &domaintest.FakeStore{}, out: &bytes.Buffer{}}
	e.cfg = Config{
		TenantID: "t1", ClientID: "c1", Scopes: []string{"User.Read", "offline_access"}, ExpectedUPN: "agent@example.com",
		Store: e.store, SecretID: secretID, Clock: e.clk, Out: e.out,
		LoginBase: srv.URL, GraphBase: srv.URL + "/v1.0", HTTP: srv.Client(),
	}
	return e
}

// run drives Enroll while a helper goroutine advances the fake clock each time
// a timer is pending.
func (e *env) run(t *testing.T) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- Enroll(context.Background(), e.cfg) }()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case err := <-done:
			return err
		case <-deadline:
			t.Fatal("enroll did not finish")
		default:
			if e.clk.PendingTimers() > 0 {
				e.clk.Advance(5 * time.Second)
			} else {
				time.Sleep(time.Millisecond)
			}
		}
	}
}

func TestEnrollDeviceCodeHappyPath(t *testing.T) {
	e := newEnv(t)
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	if e.f.dcForm.Get("client_id") != "c1" || e.f.dcForm.Get("scope") != "User.Read offline_access" {
		t.Fatalf("devicecode form %v", e.f.dcForm)
	}
	out := e.out.String()
	if !strings.Contains(out, "ABCD-1234") || !strings.Contains(out, "https://microsoft.com/devicelogin") {
		t.Fatalf("operator output %q", out)
	}
	if strings.Contains(out, "DEV") && strings.Contains(out, "device_code") {
		t.Fatal("device code leaked")
	}
	pf := e.f.pollForms[0]
	if pf.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || pf.Get("device_code") != "DEV" || pf.Get("client_id") != "c1" {
		t.Fatalf("poll form %v", pf)
	}
	got, err := e.store.Get(context.Background(), secretID)
	if err != nil || got.Value.Reveal() != "rt-1" {
		t.Fatalf("store %v %v", got, err)
	}
	if e.f.meAuth != "Bearer at" {
		t.Fatalf("me auth %q", e.f.meAuth)
	}
	if strings.Contains(out, "rt-1") || strings.Contains(out, "at") && strings.Contains(out, "Bearer") {
		t.Fatal("tokens leaked to output")
	}
}

func TestEnrollReplacesExistingTokenWithCAS(t *testing.T) {
	e := newEnv(t)
	_, _ = e.store.Put(context.Background(), secretID, domain.NewSecret("rt-old"), "")
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	got, _ := e.store.Get(context.Background(), secretID)
	if got.Value.Reveal() != "rt-1" {
		t.Fatal("not replaced")
	}
}

func TestEnrollSlowDownIncreasesInterval(t *testing.T) {
	e := newEnv(t)
	e.f.polls = []pollAns{{400, `{"error":"slow_down"}`}, {400, `{"error":"authorization_pending"}`},
		{200, `{"access_token":"at","refresh_token":"rt-1","expires_in":3600}`}}
	e.cfg.ExpectedUPN = ""
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	if len(e.f.pollForms) != 3 {
		t.Fatalf("polls=%d", len(e.f.pollForms))
	}
}

func TestEnrollTerminalDeviceErrors(t *testing.T) {
	for _, code := range []string{"authorization_declined", "access_denied", "expired_token", "bad_verification_code"} {
		e := newEnv(t)
		e.f.polls = []pollAns{{400, `{"error":"` + code + `"}`}}
		err := e.run(t)
		if !errors.Is(err, domain.ErrReauthRequired) {
			t.Fatalf("%s: %v", code, err)
		}
		if e.store.Puts != 0 {
			t.Fatal("must not store")
		}
	}
	e := newEnv(t)
	e.f.polls = []pollAns{{400, `{"error":"invalid_client"}`}}
	if err := e.run(t); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("invalid_client: %v", err)
	}
	e = newEnv(t)
	e.f.polls = []pollAns{{503, `x`}}
	if err := e.run(t); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("5xx: %v", err)
	}
}

func TestEnrollDeviceCodeExpiresLocally(t *testing.T) {
	e := newEnv(t)
	e.f.dcBody = `{"device_code":"DEV","user_code":"U","verification_uri":"https://v","expires_in":12,"interval":5}`
	e.f.polls = []pollAns{{400, `{"error":"authorization_pending"}`}}
	err := e.run(t)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("got %v", err)
	}
}

func TestEnrollNoRefreshTokenMeansOfflineAccessMissing(t *testing.T) {
	e := newEnv(t)
	e.f.polls = []pollAns{{200, `{"access_token":"at","expires_in":3600}`}}
	err := e.run(t)
	if !errors.Is(err, domain.ErrProvider) || !strings.Contains(err.Error(), "offline_access") {
		t.Fatalf("got %v", err)
	}
	if e.store.Puts != 0 {
		t.Fatal("stored")
	}
}

func TestEnrollWrongUserIsRefusedAndNotStored(t *testing.T) {
	e := newEnv(t)
	e.f.meBody = `{"userPrincipalName":"human@example.com"}`
	err := e.run(t)
	if !errors.Is(err, domain.ErrPolicy) {
		t.Fatalf("got %v", err)
	}
	if e.store.Puts != 0 {
		t.Fatal("stored refresh token of wrong user")
	}
}

func TestEnrollStoreFailure(t *testing.T) {
	e := newEnv(t)
	e.store.PutErr = errors.New("denied")
	err := e.run(t)
	if err == nil || strings.Contains(err.Error(), "rt-1") {
		t.Fatalf("got %v", err)
	}
}

func TestEnrollDeviceCodeEndpointFailures(t *testing.T) {
	e := newEnv(t)
	e.f.dcStatus, e.f.dcBody = 400, `{"error":"invalid_request"}`
	if err := e.run(t); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("400: %v", err)
	}
	e = newEnv(t)
	e.f.dcStatus, e.f.dcBody = 500, ``
	if err := e.run(t); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("500: %v", err)
	}
	e = newEnv(t)
	e.f.dcBody = `{"user_code":"x"}`
	if err := e.run(t); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("incomplete: %v", err)
	}
	e = newEnv(t)
	e.f.dcBody = `junk`
	if err := e.run(t); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("junk: %v", err)
	}
}

func TestEnrollContextCancelled(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Enroll(ctx, e.cfg) }()
	for e.clk.PendingTimers() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestEnrollConfigValidation(t *testing.T) {
	e := newEnv(t)
	for name, mut := range map[string]func(*Config){
		"tenant": func(c *Config) { c.TenantID = "" }, "client": func(c *Config) { c.ClientID = "" },
		"scopes": func(c *Config) { c.Scopes = []string{"User.Read"} }, "store": func(c *Config) { c.Store = nil },
		"secret": func(c *Config) { c.SecretID = "" }, "clock": func(c *Config) { c.Clock = nil },
		"slash": func(c *Config) { c.TenantID = "a/b" },
	} {
		c := e.cfg
		mut(&c)
		if err := Enroll(context.Background(), c); !errors.Is(err, domain.ErrConfig) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestEnrollNetworkErrors(t *testing.T) {
	e := newEnv(t)
	e.cfg.LoginBase = "http://127.0.0.1:1"
	if err := e.run(t); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("devicecode net: %v", err)
	}
}

func TestEnrollPollNetworkAndOtherErrors(t *testing.T) {
	e := newEnv(t)
	e.f.polls = []pollAns{{400, `{"error":"invalid_request"}`}}
	if err := e.run(t); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("other: %v", err)
	}
	e = newEnv(t)
	e.f.polls = []pollAns{{429, `{}`}}
	if err := e.run(t); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("429: %v", err)
	}
}

func TestEnrollMeFailures(t *testing.T) {
	e := newEnv(t)
	e.f.meBody = `junk`
	if err := e.run(t); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("junk: %v", err)
	}
	e = newEnv(t)
	e.cfg.GraphBase = "http://127.0.0.1:1"
	if err := e.run(t); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("net: %v", err)
	}
}

func TestEnrollDefaultsAndStoreReadFailure(t *testing.T) {
	e := newEnv(t)
	e.cfg.Out, e.cfg.ExpectedUPN = nil, ""
	e.f.dcBody = `{"device_code":"D","user_code":"U","verification_uri":"https://v"}` // default expiry/interval
	if err := e.run(t); err != nil {
		t.Fatal(err)
	}
	e = newEnv(t)
	e.cfg.Store = &errStore{}
	if err := e.run(t); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("get err: %v", err)
	}
	e = newEnv(t)
	e.cfg.Store = &errStore{conflict: true, notFound: true}
	if err := e.run(t); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("conflict: %v", err)
	}
}

type errStore struct{ conflict, notFound bool }

func (s *errStore) Get(context.Context, string) (domain.SecretValue, error) {
	if s.notFound {
		return domain.SecretValue{}, domain.ErrNotFound
	}
	return domain.SecretValue{}, errors.New("boom")
}

func (s *errStore) Put(context.Context, string, domain.SecretString, string) (string, error) {
	return "", domain.ErrVersionConflict
}

// FR-R08: a 307 on the device-code endpoint must not be followed.
func TestEnrollDoesNotFollowRedirect(t *testing.T) {
	var hits atomic.Int32
	second := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer second.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.URL+"/dc", http.StatusTemporaryRedirect)
	}))
	defer first.Close()
	e := newEnv(t)
	e.cfg.LoginBase, e.cfg.GraphBase, e.cfg.HTTP = first.URL, first.URL, &http.Client{}
	if err := Enroll(context.Background(), e.cfg); err == nil {
		t.Fatal("expected an error from the 307")
	}
	if hits.Load() != 0 {
		t.Fatalf("redirect target received %d requests", hits.Load())
	}
}
