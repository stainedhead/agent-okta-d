package github

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/domain/domaintest"
	ghprov "github.com/stainedhead/agent-okta-d/internal/provider/github"
)

const key = "agents/x/github"

type env struct {
	opt   Options
	store *domaintest.FakeStore
	clk   *domaintest.FakeClock
	out   *bytes.Buffer
	srv   *httptest.Server
}

func newEnv(t *testing.T, mode ghprov.Mode, h http.HandlerFunc) *env {
	t.Helper()
	e := &env{store: &domaintest.FakeStore{}, out: &bytes.Buffer{}}
	deps := domaintest.NewFakeDeps()
	e.clk = deps.ClockV.(*domaintest.FakeClock)
	deps.Stores["aws"] = e.store
	e.srv = httptest.NewServer(h)
	t.Cleanup(e.srv.Close)
	p, err := ghprov.New(ghprov.Config{APIBase: e.srv.URL, Mode: mode, Login: "agent-x_acme", StoreName: "aws", SecretID: key, OAuthClientID: "cid", HTTPClient: e.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	e.opt = Options{Provider: p, Deps: deps, Out: e.out}
	return e
}

func userHandler(login string, header string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user" {
			w.WriteHeader(404)
			return
		}
		if header != "" {
			w.Header().Set(ghprov.ExpiryHeader, header)
		}
		_, _ = w.Write([]byte(`{"id":7,"login":"` + login + `"}`))
	}
}

func stored(t *testing.T, e *env) ghprov.Stored {
	t.Helper()
	v, err := e.store.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ghprov.ParseStored(v.Value)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEnrollPATStoresVerifiedToken(t *testing.T) {
	e := newEnv(t, ghprov.ModePAT, userHandler("agent-x_acme", ""))
	exp := e.clk.Now().Add(90 * 24 * time.Hour)
	res, err := EnrollPAT(context.Background(), e.opt, strings.NewReader("ghp_pasted\n"), exp)
	if err != nil {
		t.Fatal(err)
	}
	s := stored(t, e)
	if s.Token != "ghp_pasted" || s.Mode != ghprov.ModePAT || !s.ExpiresAt.Equal(exp) {
		t.Fatalf("%+v", s)
	}
	if res.Login != "agent-x_acme" || !res.ExpiresAt.Equal(exp) || len(res.Warnings) != 0 {
		t.Fatalf("%+v", res)
	}
	if strings.Contains(e.out.String(), "ghp_pasted") {
		t.Fatal("token printed")
	}
}

func TestA05_EnrollPATReadsExpiryFromHeader(t *testing.T) {
	e := newEnv(t, ghprov.ModePAT, userHandler("agent-x_acme", "2027-01-01 00:00:00 UTC"))
	res, err := EnrollPAT(context.Background(), e.opt, strings.NewReader("ghp_x"), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	if !res.ExpiresAt.Equal(want) || !stored(t, e).ExpiresAt.Equal(want) {
		t.Fatalf("%+v", res)
	}
}

func TestEnrollPATExplicitExpiryWinsOverHeader(t *testing.T) {
	e := newEnv(t, ghprov.ModePAT, userHandler("agent-x_acme", "2027-01-01 00:00:00 UTC"))
	exp := e.clk.Now().Add(100 * 24 * time.Hour)
	res, _ := EnrollPAT(context.Background(), e.opt, strings.NewReader("ghp_x"), exp)
	if !res.ExpiresAt.Equal(exp) {
		t.Fatalf("%+v", res)
	}
}

func TestEnrollPATWarnings(t *testing.T) {
	e := newEnv(t, ghprov.ModePAT, userHandler("agent-x_acme", ""))
	res, err := EnrollPAT(context.Background(), e.opt, strings.NewReader("ghp_x"), time.Time{})
	if err != nil || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "expiry unknown") {
		t.Fatalf("%+v %v", res, err)
	}
	res, err = EnrollPAT(context.Background(), e.opt, strings.NewReader("ghp_x"), e.clk.Now().Add(10*24*time.Hour))
	if err != nil || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "10 days") {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestEnrollPATRefusesExpired(t *testing.T) {
	e := newEnv(t, ghprov.ModePAT, userHandler("agent-x_acme", ""))
	_, err := EnrollPAT(context.Background(), e.opt, strings.NewReader("ghp_x"), e.clk.Now().Add(-time.Hour))
	if !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("got %v", err)
	}
	if e.store.Puts != 0 {
		t.Fatal("must not store")
	}
}

func TestEnrollPATBadInput(t *testing.T) {
	e := newEnv(t, ghprov.ModePAT, userHandler("agent-x_acme", ""))
	for _, in := range []string{"", "  \n", "two words", strings.Repeat("a", 70000)} {
		if _, err := EnrollPAT(context.Background(), e.opt, strings.NewReader(in), time.Time{}); !errors.Is(err, domain.ErrConfig) {
			t.Errorf("%.10q: got %v", in, err)
		}
	}
	if e.store.Puts != 0 {
		t.Fatal("must not store")
	}
}

func TestEnrollPATWrongUserNotStored(t *testing.T) {
	e := newEnv(t, ghprov.ModePAT, userHandler("someone-else", ""))
	_, err := EnrollPAT(context.Background(), e.opt, strings.NewReader("ghp_x"), time.Time{})
	if !errors.Is(err, domain.ErrProvider) || strings.Contains(err.Error(), "ghp_x") {
		t.Fatalf("got %v", err)
	}
	if e.store.Puts != 0 {
		t.Fatal("must not store a token for the wrong user")
	}
}

func TestEnrollPATRejectedToken(t *testing.T) {
	e := newEnv(t, ghprov.ModePAT, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) })
	if _, err := EnrollPAT(context.Background(), e.opt, strings.NewReader("ghp_x"), time.Time{}); !errors.Is(err, domain.ErrReauthRequired) {
		t.Fatalf("got %v", err)
	}
}

func TestEnrollPATReplacesExistingUsingVersion(t *testing.T) {
	e := newEnv(t, ghprov.ModePAT, userHandler("agent-x_acme", ""))
	for _, tok := range []string{"ghp_one", "ghp_two"} {
		if _, err := EnrollPAT(context.Background(), e.opt, strings.NewReader(tok), time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	if stored(t, e).Token != "ghp_two" {
		t.Fatal("not replaced")
	}
}

func TestEnrollStoreFailures(t *testing.T) {
	e := newEnv(t, ghprov.ModePAT, userHandler("agent-x_acme", ""))
	e.store.PutErr = errors.New("kms down")
	if _, err := EnrollPAT(context.Background(), e.opt, strings.NewReader("ghp_x"), time.Time{}); err == nil || !strings.Contains(err.Error(), "kms down") {
		t.Fatalf("got %v", err)
	}
	e.store.PutErr = domain.ErrVersionConflict
	if _, err := EnrollPAT(context.Background(), e.opt, strings.NewReader("ghp_x"), time.Time{}); !errors.Is(err, domain.ErrVersionConflict) {
		t.Fatalf("got %v", err)
	}
	// missing store config
	d := domaintest.NewFakeDeps()
	e.opt.Deps = d
	if _, err := EnrollPAT(context.Background(), e.opt, strings.NewReader("ghp_x"), time.Time{}); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("got %v", err)
	}
}

func TestEnrollRequiresMode(t *testing.T) {
	e := newEnv(t, ghprov.ModeOAuthDevice, userHandler("agent-x_acme", ""))
	if _, err := EnrollPAT(context.Background(), e.opt, strings.NewReader("x"), time.Time{}); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("got %v", err)
	}
	e = newEnv(t, ghprov.ModePAT, userHandler("agent-x_acme", ""))
	if _, err := EnrollDevice(context.Background(), e.opt, DeviceOptions{}); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("got %v", err)
	}
}

// ---- device flow ----

type deviceServer struct {
	mu        sync.Mutex
	polls     int
	script    []string // JSON bodies returned by successive token polls
	codeBody  string
	codeForm  map[string]string
	pollForms []map[string]string
	login     string
}

func (d *deviceServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		_ = r.ParseForm()
		form := map[string]string{}
		for k := range r.PostForm {
			form[k] = r.PostForm.Get(k)
		}
		switch r.URL.Path {
		case "/login/device/code":
			d.codeForm = form
			_, _ = w.Write([]byte(d.codeBody))
		case "/login/oauth/access_token":
			d.pollForms = append(d.pollForms, form)
			i := min(d.polls, len(d.script)-1)
			d.polls++
			_, _ = w.Write([]byte(d.script[i]))
		case "/user":
			_, _ = w.Write([]byte(`{"id":7,"login":"` + d.login + `"}`))
		default:
			w.WriteHeader(404)
		}
	}
}

func (d *deviceServer) pollCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.polls
}

const codeOK = `{"device_code":"DEV123","user_code":"WDJB-MJHT","verification_uri":"https://github.com/login/device","expires_in":900,"interval":5}`

// drive advances the fake clock until the enrollment goroutine finishes.
func drive(t *testing.T, e *env, run func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- run() }()
	for {
		select {
		case err := <-done:
			return err
		case <-time.After(2 * time.Millisecond):
			if e.clk.PendingTimers() > 0 {
				e.clk.Advance(time.Second)
			}
		}
	}
}

func newDeviceEnv(t *testing.T, ds *deviceServer) *env {
	t.Helper()
	return newEnv(t, ghprov.ModeOAuthDevice, ds.handler())
}

func TestEnrollDeviceHappyPath(t *testing.T) {
	ds := &deviceServer{codeBody: codeOK, login: "agent-x_acme", script: []string{
		`{"error":"authorization_pending"}`,
		`{"error":"authorization_pending"}`,
		`{"access_token":"gho_dev","token_type":"bearer","scope":"repo,read:org"}`,
	}}
	e := newDeviceEnv(t, ds)
	var res Result
	err := drive(t, e, func() error {
		var err error
		res, err = EnrollDevice(context.Background(), e.opt, DeviceOptions{})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if ds.codeForm["client_id"] != "cid" || ds.codeForm["scope"] != DefaultScope {
		t.Fatalf("code request %v", ds.codeForm)
	}
	f := ds.pollForms[0]
	if f["client_id"] != "cid" || f["device_code"] != "DEV123" || f["grant_type"] != "urn:ietf:params:oauth:grant-type:device_code" {
		t.Fatalf("poll form %v", f)
	}
	out := e.out.String()
	if !strings.Contains(out, "WDJB-MJHT") || !strings.Contains(out, "https://github.com/login/device") || strings.Contains(out, "gho_dev") || strings.Contains(out, "DEV123") {
		t.Fatalf("prompt: %q", out)
	}
	s := stored(t, e)
	if s.Token != "gho_dev" || s.Mode != ghprov.ModeOAuthDevice || s.Scope != "repo,read:org" || !s.ExpiresAt.IsZero() {
		t.Fatalf("%+v", s)
	}
	if res.Login != "agent-x_acme" || ds.pollCount() != 3 {
		t.Fatalf("%+v polls=%d", res, ds.pollCount())
	}
}

func TestEnrollDeviceHonoursIntervalAndSlowDown(t *testing.T) {
	ds := &deviceServer{codeBody: codeOK, login: "agent-x_acme", script: []string{
		`{"error":"slow_down"}`,
		`{"access_token":"gho_dev","scope":""}`,
	}}
	e := newDeviceEnv(t, ds)
	start := e.clk.Now()
	err := drive(t, e, func() error { _, err := EnrollDevice(context.Background(), e.opt, DeviceOptions{}); return err })
	if err != nil {
		t.Fatal(err)
	}
	// 5 s before first poll, then 5+5 s after slow_down (RFC 8628 section 3.5).
	if got := e.clk.Now().Sub(start); got < 15*time.Second || got > 17*time.Second {
		t.Fatalf("waited %v, want ~15s", got)
	}
}

func TestEnrollDeviceErrors(t *testing.T) {
	cases := []struct {
		name string
		code string
		poll string
		is   error
	}{
		{"denied", codeOK, `{"error":"access_denied"}`, domain.ErrAuthDefinitive},
		{"expired", codeOK, `{"error":"expired_token"}`, domain.ErrProvider},
		{"unsupported", codeOK, `{"error":"device_flow_disabled","error_description":"off"}`, domain.ErrProvider},
		{"bad client", codeOK, `{"error":"incorrect_client_credentials"}`, domain.ErrProvider},
		{"empty token", codeOK, `{"access_token":""}`, domain.ErrProvider},
		{"code error", `{"error":"unauthorized_client"}`, ``, domain.ErrProvider},
		{"code garbage", `nope`, ``, domain.ErrProvider},
		{"code incomplete", `{"device_code":"x"}`, ``, domain.ErrProvider},
		{"poll garbage", codeOK, `<html>`, domain.ErrProvider},
	}
	for _, c := range cases {
		ds := &deviceServer{codeBody: c.code, login: "agent-x_acme", script: []string{c.poll}}
		e := newDeviceEnv(t, ds)
		err := drive(t, e, func() error { _, err := EnrollDevice(context.Background(), e.opt, DeviceOptions{}); return err })
		if !errors.Is(err, c.is) {
			t.Errorf("%s: got %v want %v", c.name, err, c.is)
		}
		if e.store.Puts != 0 {
			t.Errorf("%s: stored", c.name)
		}
	}
}

func TestEnrollDeviceTimesOutOnLocalDeadline(t *testing.T) {
	ds := &deviceServer{codeBody: `{"device_code":"D","user_code":"U","verification_uri":"v","expires_in":12,"interval":5}`, login: "agent-x_acme", script: []string{`{"error":"authorization_pending"}`}}
	e := newDeviceEnv(t, ds)
	err := drive(t, e, func() error { _, err := EnrollDevice(context.Background(), e.opt, DeviceOptions{}); return err })
	if !errors.Is(err, domain.ErrProvider) || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("got %v", err)
	}
}

func TestEnrollDeviceContextCancel(t *testing.T) {
	ds := &deviceServer{codeBody: codeOK, login: "agent-x_acme", script: []string{`{"error":"authorization_pending"}`}}
	e := newDeviceEnv(t, ds)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := EnrollDevice(ctx, e.opt, DeviceOptions{}); done <- err }()
	for e.clk.PendingTimers() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestEnrollDeviceWrongUserNotStored(t *testing.T) {
	ds := &deviceServer{codeBody: codeOK, login: "intruder", script: []string{`{"access_token":"gho_dev"}`}}
	e := newDeviceEnv(t, ds)
	err := drive(t, e, func() error { _, err := EnrollDevice(context.Background(), e.opt, DeviceOptions{}); return err })
	if !errors.Is(err, domain.ErrProvider) || e.store.Puts != 0 {
		t.Fatalf("err=%v puts=%d", err, e.store.Puts)
	}
}

func TestEnrollDeviceCustomScopeAndTransientPoll(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	ds := &deviceServer{codeBody: codeOK, login: "agent-x_acme", script: []string{`{"access_token":"gho_dev"}`}}
	inner := ds.handler()
	e := newEnv(t, ghprov.ModeOAuthDevice, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login/oauth/access_token" {
			mu.Lock()
			calls++
			c := calls
			mu.Unlock()
			if c == 1 {
				w.WriteHeader(502)
				return
			}
		}
		inner(w, r)
	})
	err := drive(t, e, func() error {
		_, err := EnrollDevice(context.Background(), e.opt, DeviceOptions{Scope: "repo"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if ds.codeForm["scope"] != "repo" {
		t.Fatalf("scope %v", ds.codeForm)
	}
}

func TestEnrollDeviceCodeRequestHTTPFailure(t *testing.T) {
	e := newEnv(t, ghprov.ModeOAuthDevice, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })
	_, err := EnrollDevice(context.Background(), e.opt, DeviceOptions{})
	if !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("got %v", err)
	}
}

func TestA06_ClientIDDefaultsToGitHubCLIApp(t *testing.T) {
	ds := &deviceServer{codeBody: codeOK, login: "agent-x_acme", script: []string{`{"access_token":"gho_dev"}`}}
	srv := httptest.NewServer(ds.handler())
	defer srv.Close()
	deps := domaintest.NewFakeDeps()
	deps.Stores["aws"] = &domaintest.FakeStore{}
	p, _ := ghprov.New(ghprov.Config{APIBase: srv.URL, Mode: ghprov.ModeOAuthDevice, Login: "agent-x_acme", StoreName: "aws", SecretID: key, HTTPClient: srv.Client()})
	e := &env{clk: deps.ClockV.(*domaintest.FakeClock), out: &bytes.Buffer{}}
	e.opt = Options{Provider: p, Deps: deps, Out: e.out}
	if err := drive(t, e, func() error { _, err := EnrollDevice(context.Background(), e.opt, DeviceOptions{}); return err }); err != nil {
		t.Fatal(err)
	}
	if ds.codeForm["client_id"] != ghprov.DefaultOAuthClientID {
		t.Fatalf("%v", ds.codeForm)
	}
}
