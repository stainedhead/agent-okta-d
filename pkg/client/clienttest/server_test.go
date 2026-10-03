package clienttest_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/pkg/client/clienttest"
)

func httpc(s *clienttest.Server) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", s.SocketPath())
	}}}
}

func do(t *testing.T, s *clienttest.Server, method, path string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), method, "http://x"+path, nil)
	resp, err := httpc(s).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b)), resp.Header
}

func TestRoutes(t *testing.T) {
	s := clienttest.New(t)
	if c, b, _ := do(t, s, "GET", "/healthz"); c != 200 || b != `{"status":"ok"}` {
		t.Fatal(c, b)
	}
	if c, b, _ := do(t, s, "GET", "/v1/status"); c != 200 || b != `{"state":"valid","providers":[]}` {
		t.Fatal(c, b)
	}
	if c, b, _ := do(t, s, "GET", "/v1/identity"); c != 200 || !strings.Contains(b, `"api_version":"v1"`) {
		t.Fatal(c, b)
	}
	for _, tc := range [][2]string{{"GET", "/nope"}, {"POST", "/v1/status"}, {"GET", "/v1/credentials/aws"}, {"GET", "/v1/credentials/aws/refresh"}, {"POST", "/v1/credentials/aws"}} {
		if c, b, _ := do(t, s, tc[0], tc[1]); c != 404 || !strings.Contains(b, "not_configured") {
			t.Fatalf("%v: %d %s", tc, c, b)
		}
	}
	if n := len(s.Requests()); n != 8 {
		t.Fatalf("requests: %d", n)
	}
}

func TestErrorsAndRaw(t *testing.T) {
	s := clienttest.New(t)
	s.SetProviderError("p", clienttest.Error{Code: clienttest.CodeDegraded, State: "degraded", RetryAfter: 30 * time.Second})
	c, b, h := do(t, s, "GET", "/v1/credentials/p")
	if c != 503 || b != `{"error":"degraded","state":"degraded","retry_after_seconds":30}` || h.Get("Retry-After") != "30" {
		t.Fatal(c, b, h)
	}
	s.SetProviderError("p", clienttest.Error{})
	if c, _, _ := do(t, s, "GET", "/v1/credentials/p"); c != 404 {
		t.Fatal(c)
	}
	for code, want := range map[string]int{clienttest.CodeReauthRequired: 401, clienttest.CodeRevoked: 403, clienttest.CodeUnauthorized: 403, clienttest.CodeNotConfigured: 404, clienttest.CodeInternal: 500, "weird": 500} {
		s.SetGlobalError(clienttest.Error{Code: code})
		if c, _, _ := do(t, s, "GET", "/v1/status"); c != want {
			t.Fatalf("%s: %d", code, c)
		}
	}
	s.SetGlobalError(clienttest.Error{})
	s.SetRaw(418, "teapot")
	if c, b, _ := do(t, s, "GET", "/v1/status"); c != 418 || b != "teapot" {
		t.Fatal(c, b)
	}
	s.SetRaw(0, "")
	if c, _, _ := do(t, s, "GET", "/v1/status"); c != 200 {
		t.Fatal(c)
	}
}

func TestDelayAbortsOnClientGone(t *testing.T) {
	s := clienttest.New(t)
	s.SetDelay(5 * time.Second)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://x/v1/status", nil)
	if _, err := httpc(s).Do(req); err == nil {
		t.Fatal("expected timeout")
	}
}

func TestDeadSocketPath(t *testing.T) {
	p := clienttest.DeadSocketPath(t)
	if _, err := net.Dial("unix", p); err == nil {
		t.Fatal("something is listening")
	}
}

func TestSettersAndRefresh(t *testing.T) {
	s := clienttest.New(t)
	exp := time.Date(2026, 10, 3, 13, 0, 0, 0, time.UTC)
	s.SetCredential("aws", clienttest.Credential{TokenType: "Bearer", AccessToken: "one", ExpiresAt: exp})
	s.SetRefreshed("aws", clienttest.Credential{TokenType: "Bearer", AccessToken: "two", ExpiresAt: exp})
	s.SetStatus(clienttest.Status{State: "degraded", Providers: []clienttest.ProviderStatus{{Provider: "aws", State: "valid", ExpiresAt: &exp}}})
	s.SetIdentity(clienttest.Identity{AgentID: "a", APIVersion: "v1"})
	if _, b, _ := do(t, s, "GET", "/v1/credentials/aws"); !strings.Contains(b, `"access_token":"one"`) {
		t.Fatal(b)
	}
	if _, b, _ := do(t, s, "POST", "/v1/credentials/aws/refresh"); !strings.Contains(b, `"access_token":"two"`) {
		t.Fatal(b)
	}
	if _, b, _ := do(t, s, "GET", "/v1/credentials/aws"); !strings.Contains(b, `"access_token":"two"`) {
		t.Fatal(b)
	}
	if _, b, _ := do(t, s, "GET", "/v1/status"); !strings.Contains(b, `"state":"degraded"`) || !strings.Contains(b, "2026-10-03T13:00:00Z") {
		t.Fatal(b)
	}
	if _, b, _ := do(t, s, "GET", "/v1/identity"); !strings.Contains(b, `"agent_id":"a"`) {
		t.Fatal(b)
	}
	got := s.Requests()
	got[0].Path = "mutated"
	if s.Requests()[0].Path == "mutated" {
		t.Fatal("Requests must return a copy")
	}
}

type fakeTB struct{ failed string }

func (*fakeTB) Helper()                          {}
func (f *fakeTB) Fatalf(format string, _ ...any) { f.failed = format; panic(f) }
func (*fakeTB) Cleanup(func())                   {}

func fatal(t *testing.T, f func(clienttest.TB)) (tb *fakeTB) {
	t.Helper()
	tb = &fakeTB{}
	defer func() {
		if r := recover(); r != tb {
			t.Fatalf("expected Fatalf, got %v", r)
		}
	}()
	f(tb)
	return tb
}

func TestSetupFailures(t *testing.T) {
	// A socket path beyond the OS limit makes Listen fail.
	long := t.TempDir() + strings.Repeat("/0123456789abcdef", 8)
	if err := os.MkdirAll(long, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", "/nonexistent-dir-for-clienttest")
	if tb := fatal(t, func(tb clienttest.TB) { clienttest.New(tb) }); !strings.Contains(tb.failed, "temp dir") {
		t.Fatal(tb.failed)
	}
	if tb := fatal(t, func(tb clienttest.TB) { clienttest.DeadSocketPath(tb) }); !strings.Contains(tb.failed, "temp dir") {
		t.Fatal(tb.failed)
	}
	t.Setenv("TMPDIR", long)
	if tb := fatal(t, func(tb clienttest.TB) { clienttest.New(tb) }); !strings.Contains(tb.failed, "listen") {
		t.Fatal(tb.failed)
	}
}
