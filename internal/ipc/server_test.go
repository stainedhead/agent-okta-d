package ipc_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/domain/domaintest"
	"github.com/stainedhead/agent-okta-d/internal/ipc"
)

type fakeBackend struct {
	mu      sync.Mutex
	cred    domain.Credential
	err     error
	status  domain.WireStatus
	calls   []string
	lastCtx context.Context
}

func (b *fakeBackend) Credential(ctx context.Context, p string) (domain.Credential, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, "get:"+p)
	b.lastCtx = ctx
	return b.cred, b.err
}

func (b *fakeBackend) Refresh(_ context.Context, p string) (domain.Credential, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, "refresh:"+p)
	return b.cred, b.err
}

func (b *fakeBackend) Status(context.Context) domain.WireStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.status
}

func (b *fakeBackend) Calls() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.calls...)
}

func goodCred() domain.Credential {
	return domain.Credential{
		Kind: domain.KindBearer, Value: domain.NewSecret("tok-SUPER-secret-123"),
		IssuedAt: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 10, 3, 13, 0, 0, 0, time.UTC),
		Meta: map[string]string{domain.MetaAudience: "api://x", domain.MetaJTI: "jti-1"},
	}
}

type env struct {
	srv    *ipc.Server
	be     *fakeBackend
	audit  *domaintest.RecordingAudit
	peer   *domaintest.FakePeerCred
	sock   string
	client *http.Client
}

func withPeer(c domain.CallerInfo, err error) func(*env) {
	return func(e *env) { e.peer.Caller, e.peer.Err = c, err }
}

func newEnv(t *testing.T, cfg ipc.Config, opts ...func(*env)) *env {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	e := &env{
		be:    &fakeBackend{cred: goodCred(), status: domain.WireStatus{State: domain.StateValid}},
		audit: &domaintest.RecordingAudit{},
		peer:  &domaintest.FakePeerCred{Caller: domain.CallerInfo{UID: 1001, GID: 2000, PID: 4242, Exe: "/usr/bin/snow"}},
		sock:  filepath.Join(dir, "s.sock"),
	}
	for _, o := range opts {
		o(e)
	}
	e.srv = ipc.New(cfg, ipc.Deps{Backend: e.be, PeerCred: e.peer, Audit: e.audit, Clock: domaintest.NewFakeClock()})
	ln, err := ipc.ListenUnix(e.sock, 0o660)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- e.srv.Serve(ln) }()
	e.client = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", e.sock)
	}, DisableKeepAlives: true}}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = e.srv.Shutdown(ctx)
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return e
}

func (e *env) do(t *testing.T, method, path string) (int, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest(method, "http://unix"+path, http.NoBody)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, strings.TrimSpace(string(b))
}

func golden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "domain", "testdata", "wire", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func baseCfg() ipc.Config {
	return ipc.Config{
		AllowGIDs: []int{2000}, AgentID: "agent-007",
		Identity: domain.WireIdentity{AgentID: "agent-007", OktaClientID: "0oaEXAMPLE", KID: "kid-1", DaemonVersion: "0.1.0", APIVersion: "v1"},
	}
}

func TestGetCredentialMatchesGoldenWire(t *testing.T) {
	e := newEnv(t, baseCfg())
	code, h, body := e.do(t, "GET", "/v1/credentials/aws")
	if code != 200 || body != golden(t, "credential.json") {
		t.Fatalf("got %d %s", code, body)
	}
	if h.Get("Content-Type") != "application/json" || h.Get("Cache-Control") != "no-store" {
		t.Errorf("headers %v", h)
	}
	ev := e.audit.Events()
	if len(ev) != 1 || ev[0].Event != domain.AuditServe || ev[0].Result != domain.ResultOK || ev[0].Provider != "aws" ||
		*ev[0].CallerUID != 1001 || *ev[0].CallerPID != 4242 || ev[0].CallerExe != "/usr/bin/snow" || ev[0].AgentID != "agent-007" || ev[0].JTI != "jti-1" {
		t.Errorf("audit %+v", ev)
	}
	if strings.Contains(mustJSON(t, ev), "tok-SUPER") {
		t.Error("audit leaked token")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRefreshIsPostAndForcesRefresh(t *testing.T) {
	e := newEnv(t, baseCfg())
	code, _, body := e.do(t, "POST", "/v1/credentials/aws/refresh")
	if code != 200 || body != golden(t, "credential.json") {
		t.Fatalf("got %d %s", code, body)
	}
	if c := e.be.Calls(); len(c) != 1 || c[0] != "refresh:aws" {
		t.Errorf("calls %v", c)
	}
	if ev := e.audit.Events(); len(ev) != 1 || ev[0].Event != domain.AuditRefresh {
		t.Errorf("audit %+v", ev)
	}
}

func TestStatusAndIdentityAndHealthz(t *testing.T) {
	e := newEnv(t, baseCfg())
	e.be.status = domain.WireStatus{State: domain.StateDegraded, Providers: []domain.WireProviderStatus{{Provider: "aws", State: domain.StateValid}}}
	code, _, body := e.do(t, "GET", "/v1/status")
	if code != 200 || !strings.Contains(body, `"state":"degraded"`) || !strings.Contains(body, `"provider":"aws"`) {
		t.Errorf("status %d %s", code, body)
	}
	code, _, body = e.do(t, "GET", "/v1/identity")
	if code != 200 || body != golden(t, "identity.json") {
		t.Errorf("identity %d %s", code, body)
	}
	code, _, body = e.do(t, "GET", "/healthz")
	if code != 200 || body != golden(t, "health.json") {
		t.Errorf("healthz %d %s", code, body)
	}
}

func TestDegradedIs503WithRetryAfterMatchingGolden(t *testing.T) {
	e := newEnv(t, baseCfg())
	e.be.err = domain.NewTransient(errors.New("okta down"), 30*time.Second)
	code, h, body := e.do(t, "GET", "/v1/credentials/aws")
	if code != 503 || h.Get("Retry-After") != "30" || body != golden(t, "error_degraded.json") {
		t.Fatalf("got %d %v %s", code, h, body)
	}
}

func TestDegradedDefaultAndRoundedRetryAfter(t *testing.T) {
	e := newEnv(t, baseCfg())
	e.be.err = domain.NewTransient(errors.New("x"), 0)
	_, h, _ := e.do(t, "GET", "/v1/credentials/aws")
	if h.Get("Retry-After") != "30" {
		t.Errorf("default Retry-After %q", h.Get("Retry-After"))
	}
	e.be.mu.Lock()
	e.be.err = domain.NewTransient(errors.New("x"), 1500*time.Millisecond)
	e.be.mu.Unlock()
	_, h, body := e.do(t, "GET", "/v1/credentials/aws")
	if h.Get("Retry-After") != "2" || !strings.Contains(body, `"retry_after_seconds":2`) {
		t.Errorf("rounded Retry-After %q %s", h.Get("Retry-After"), body)
	}
}

func TestBackendErrorMapping(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		body   string
	}{
		{"revoked", domain.ErrRevoked, 403, `{"error":"revoked","state":"revoked"}`},
		{"reauth", domain.Wrap(domain.ErrReauthRequired, errors.New("x")), 401, `{"error":"reauth_required","state":"reauth_required"}`},
		{"not configured", ipc.ErrNotConfigured, 404, `{"error":"not_configured"}`},
		{"internal", errors.New("boom secret-detail"), 500, `{"error":"internal"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, baseCfg())
			e.be.err = tc.err
			code, _, body := e.do(t, "GET", "/v1/credentials/aws")
			if code != tc.status || body != tc.body {
				t.Errorf("got %d %s", code, body)
			}
			if ev := e.audit.Events(); len(ev) != 1 || ev[0].Result != domain.ResultError {
				t.Errorf("audit %+v", ev)
			}
		})
	}
}

func TestRevokedDaemonReturns403EvenIfBackendHasCredential(t *testing.T) {
	e := newEnv(t, baseCfg())
	e.be.status = domain.WireStatus{State: domain.StateRevoked}
	for _, req := range [][2]string{{"GET", "/v1/credentials/aws"}, {"POST", "/v1/credentials/aws/refresh"}} {
		code, _, body := e.do(t, req[0], req[1])
		if code != 403 || body != `{"error":"revoked","state":"revoked"}` {
			t.Errorf("%v: %d %s", req, code, body)
		}
	}
	if len(e.be.Calls()) != 0 {
		t.Errorf("backend consulted: %v", e.be.Calls())
	}
}

func TestMalformedCredentialIsNeverServed(t *testing.T) {
	e := newEnv(t, baseCfg())
	e.be.cred = domain.Credential{Kind: domain.KindBearer}
	code, _, body := e.do(t, "GET", "/v1/credentials/aws")
	if code != 500 || body != `{"error":"internal"}` {
		t.Errorf("got %d %s", code, body)
	}
}

func TestGIDAllowList(t *testing.T) {
	cfg := baseCfg()
	cfg.ProviderGIDs = map[string][]int{"snow": {3000}, "locked": {}}
	tests := []struct {
		name   string
		caller domain.CallerInfo
		path   string
		status int
	}{
		{"default list allows", domain.CallerInfo{GID: 2000}, "/v1/credentials/aws", 200},
		{"unknown gid denied", domain.CallerInfo{GID: 9999}, "/v1/credentials/aws", 403},
		{"supplementary group allowed", domain.CallerInfo{GID: 9999, Groups: []int{1, 2000}}, "/v1/credentials/aws", 200},
		{"per-provider overrides default", domain.CallerInfo{GID: 2000}, "/v1/credentials/snow", 403},
		{"per-provider gid allowed", domain.CallerInfo{GID: 3000}, "/v1/credentials/snow", 200},
		{"per-provider gid not allowed elsewhere", domain.CallerInfo{GID: 3000}, "/v1/credentials/aws", 403},
		{"empty provider list denies all", domain.CallerInfo{GID: 2000}, "/v1/credentials/locked", 403},
		{"status needs some allowed gid", domain.CallerInfo{GID: 3000}, "/v1/status", 200},
		{"status denied for unknown gid", domain.CallerInfo{GID: 9999}, "/v1/status", 403},
		{"identity denied for unknown gid", domain.CallerInfo{GID: 9999}, "/v1/identity", 403},
		{"healthz needs only a verified peer", domain.CallerInfo{GID: 9999}, "/healthz", 200},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, cfg, withPeer(tc.caller, nil))
			code, _, body := e.do(t, "GET", tc.path)
			if code != tc.status {
				t.Fatalf("got %d %s want %d", code, body, tc.status)
			}
			if tc.status == 403 {
				if body != `{"error":"unauthorized"}` {
					t.Errorf("body %s", body)
				}
				if len(e.be.Calls()) != 0 {
					t.Errorf("backend consulted for denied caller")
				}
				ev := e.audit.Events()
				if len(ev) != 1 || ev[0].Result != domain.ResultDenied || ev[0].ErrorClass != "policy" {
					t.Errorf("audit %+v", ev)
				}
			}
		})
	}
}

func TestPeerCredFailureIsDeny(t *testing.T) {
	e := newEnv(t, baseCfg(), withPeer(domain.CallerInfo{}, errors.New("no cred")))
	for _, p := range []string{"/v1/credentials/aws", "/healthz", "/v1/status"} {
		code, _, body := e.do(t, "GET", p)
		if code != 403 || body != `{"error":"unauthorized"}` {
			t.Errorf("%s: %d %s", p, code, body)
		}
	}
	if len(e.be.Calls()) != 0 {
		t.Error("backend consulted")
	}
	ev := e.audit.Events()
	if len(ev) == 0 || ev[0].CallerUID != nil {
		t.Errorf("audit should have no caller: %+v", ev)
	}
}

func TestNilPeerCredReaderDenies(t *testing.T) {
	be := &fakeBackend{cred: goodCred()}
	srv := ipc.New(baseCfg(), ipc.Deps{Backend: be})
	dir, _ := os.MkdirTemp("/tmp", "ipc")
	defer func() { _ = os.RemoveAll(dir) }()
	ln, err := ipc.ListenUnix(filepath.Join(dir, "s"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, "s"))
	}}}
	resp, err := c.Get("http://unix/v1/credentials/aws")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("status %d", resp.StatusCode)
	}
}

func TestRoutingErrors(t *testing.T) {
	e := newEnv(t, baseCfg())
	tests := []struct {
		method, path string
		status       int
		allow        string
	}{
		{"POST", "/v1/credentials/aws", 405, "GET"},
		{"GET", "/v1/credentials/aws/refresh", 405, "POST"},
		{"POST", "/v1/status", 405, "GET"},
		{"GET", "/nope", 404, ""},
		{"GET", "/v1/credentials/", 404, ""},
		{"GET", "/v1/credentials/a/b", 404, ""},
		{"POST", "/v1/credentials//refresh", 404, ""},
	}
	for _, tc := range tests {
		code, h, body := e.do(t, tc.method, tc.path)
		if code != tc.status || h.Get("Allow") != tc.allow {
			t.Errorf("%s %s: %d allow=%q %s", tc.method, tc.path, code, h.Get("Allow"), body)
		}
	}
	if len(e.be.Calls()) != 0 {
		t.Errorf("backend consulted: %v", e.be.Calls())
	}
}

func TestNoTokenInErrorBodiesOrHeaders(t *testing.T) {
	e := newEnv(t, baseCfg())
	e.be.err = domain.Wrap(domain.ErrTransient, errors.New("tok-SUPER-secret-123"))
	_, h, body := e.do(t, "GET", "/v1/credentials/aws")
	if strings.Contains(body, "SUPER") || strings.Contains(mustJSON(t, h), "SUPER") {
		t.Error("leak")
	}
}

func TestListenUnix(t *testing.T) {
	dir, _ := os.MkdirTemp("/tmp", "ipc")
	defer func() { _ = os.RemoveAll(dir) }()
	p := filepath.Join(dir, "s.sock")

	ln, err := ipc.ListenUnix(p, 0o660)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o660 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if _, err := ipc.ListenUnix(p, 0o660); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Errorf("live socket: %v", err)
	}
	// Leave a stale socket file behind: close the fd without unlinking.
	ul := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(false)
	_ = ln.Close()
	ln2, err := ipc.ListenUnix(p, 0o600)
	if err != nil {
		t.Fatalf("stale socket should be replaced: %v", err)
	}
	_ = ln2.Close()

	f := filepath.Join(dir, "regular")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ipc.ListenUnix(f, 0o600); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("regular file: %v", err)
	}
	if _, err := ipc.ListenUnix(filepath.Join(dir, "missing", "s"), 0o600); err == nil {
		t.Error("expected bind error")
	}
}

func TestServeReturnsListenerError(t *testing.T) {
	srv := ipc.New(baseCfg(), ipc.Deps{Backend: &fakeBackend{}, PeerCred: &domaintest.FakePeerCred{}})
	ln := &failListener{}
	if err := srv.Serve(ln); err == nil {
		t.Error("want error")
	}
}

type failListener struct{}

func (*failListener) Accept() (net.Conn, error) { return nil, errors.New("accept failed") }
func (*failListener) Close() error              { return nil }
func (*failListener) Addr() net.Addr            { return &net.UnixAddr{} }
