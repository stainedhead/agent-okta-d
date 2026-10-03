package client_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/pkg/client"
	"github.com/stainedhead/agent-okta-d/pkg/client/clienttest"
)

var (
	t0   = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	cred = clienttest.Credential{TokenType: "Bearer", AccessToken: "tok-SUPER-secret-123", IssuedAt: t0, ExpiresAt: t0.Add(time.Hour), Audience: "api://x"}
)

func newPair(t *testing.T, opts ...client.Option) (*client.Client, *clienttest.Server) {
	t.Helper()
	srv := clienttest.New(t)
	c := client.New(append([]client.Option{client.WithSocketPath(srv.SocketPath())}, opts...)...)
	t.Cleanup(c.Close)
	return c, srv
}

func TestCredential(t *testing.T) {
	c, srv := newPair(t)
	srv.SetCredential("aws", cred)
	got, err := c.Credential(context.Background(), "aws")
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken.Reveal() != cred.AccessToken || got.TokenType != "Bearer" || got.Audience != "api://x" ||
		!got.IssuedAt.Equal(t0) || !got.ExpiresAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("unexpected credential %v", got)
	}
	if got.ExpiredAt(t0) || !got.ExpiredAt(t0.Add(time.Hour)) {
		t.Fatal("ExpiredAt wrong")
	}
	if strings.Contains(got.String(), cred.AccessToken) || strings.Contains(fmt.Sprintf("%+v %#v %v", got, got, got), cred.AccessToken) {
		t.Fatal("token leaked in formatting")
	}
	if reqs := srv.Requests(); len(reqs) != 1 || reqs[0].Method != "GET" || reqs[0].Path != "/v1/credentials/aws" {
		t.Fatalf("requests: %v", reqs)
	}
}

func TestCredentialProviderEscaped(t *testing.T) {
	c, srv := newPair(t)
	srv.SetCredential("a/b c", cred)
	if _, err := c.Credential(context.Background(), "a/b c"); err != nil {
		t.Fatal(err)
	}
	if p := srv.Requests()[0].Path; p != "/v1/credentials/a%2Fb%20c" {
		t.Fatalf("path %q", p)
	}
}

func TestRefresh(t *testing.T) {
	c, srv := newPair(t)
	srv.SetCredential("aws", cred)
	next := cred
	next.AccessToken = "tok-next"
	srv.SetRefreshed("aws", next)
	got, err := c.Refresh(context.Background(), "aws")
	if err != nil || got.AccessToken.Reveal() != "tok-next" {
		t.Fatalf("%v %v", got, err)
	}
	if r := srv.Requests()[0]; r.Method != "POST" || r.Path != "/v1/credentials/aws/refresh" {
		t.Fatalf("request %v", r)
	}
	got, err = c.Credential(context.Background(), "aws")
	if err != nil || got.AccessToken.Reveal() != "tok-next" {
		t.Fatalf("refreshed credential not current: %v %v", got, err)
	}
}

func TestEmptyProvider(t *testing.T) {
	c, _ := newPair(t)
	for _, f := range []func() error{
		func() error { _, err := c.Credential(context.Background(), ""); return err },
		func() error { _, err := c.Refresh(context.Background(), ""); return err },
	} {
		if err := f(); !errors.Is(err, client.ErrNotConfigured) {
			t.Fatalf("got %v", err)
		}
	}
}

func TestStatusAndIdentity(t *testing.T) {
	c, srv := newPair(t)
	exp := t0.Add(time.Hour)
	srv.SetStatus(clienttest.Status{State: "degraded", Providers: []clienttest.ProviderStatus{
		{Provider: "aws", State: "valid", ExpiresAt: &exp},
		{Provider: "snow", State: "degraded", LastError: "transient", RetryAfterSeconds: 12},
	}})
	st, err := c.Status(context.Background())
	if err != nil || st.State != client.StateDegraded || len(st.Providers) != 2 ||
		st.Providers[0].ExpiresAt == nil || !st.Providers[0].ExpiresAt.Equal(exp) ||
		st.Providers[1].RetryAfterSeconds != 12 || st.Providers[1].LastError != "transient" {
		t.Fatalf("%+v %v", st, err)
	}
	srv.SetIdentity(clienttest.Identity{AgentID: "a1", OktaClientID: "0oa", KID: "k", DaemonVersion: "1", APIVersion: "v1"})
	id, err := c.Identity(context.Background())
	if err != nil || id != (client.Identity{AgentID: "a1", OktaClientID: "0oa", KID: "k", DaemonVersion: "1", APIVersion: "v1"}) {
		t.Fatalf("%+v %v", id, err)
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		name  string
		e     clienttest.Error
		want  error
		retry time.Duration
	}{
		{"reauth", clienttest.Error{Code: clienttest.CodeReauthRequired, State: "reauth_required"}, client.ErrReauthRequired, 0},
		{"revoked", clienttest.Error{Code: clienttest.CodeRevoked, State: "revoked"}, client.ErrRevoked, 0},
		{"unauthorized", clienttest.Error{Code: clienttest.CodeUnauthorized}, client.ErrUnauthorized, 0},
		{"not_configured", clienttest.Error{Code: clienttest.CodeNotConfigured}, client.ErrNotConfigured, 0},
		{"degraded", clienttest.Error{Code: clienttest.CodeDegraded, State: "degraded", RetryAfter: 30 * time.Second}, client.ErrDegraded, 30 * time.Second},
		// Body code wins over status: a "revoked" body on 500 is still revoked.
		{"code beats status", clienttest.Error{Code: clienttest.CodeRevoked, HTTPStatus: 500}, client.ErrRevoked, 0},
		// Status is the fallback when the body has no known code.
		{"bare 401", clienttest.Error{Code: "x", HTTPStatus: 401}, client.ErrReauthRequired, 0},
		{"bare 403 fails closed as unauthorized", clienttest.Error{Code: "x", HTTPStatus: 403}, client.ErrUnauthorized, 0},
		{"bare 404", clienttest.Error{Code: "x", HTTPStatus: 404}, client.ErrNotConfigured, 0},
		{"bare 503", clienttest.Error{Code: "x", HTTPStatus: 503, RetryAfter: 7 * time.Second}, client.ErrDegraded, 7 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, srv := newPair(t)
			srv.SetProviderError("p", tc.e)
			for _, call := range []func() error{
				func() error { _, err := c.Credential(context.Background(), "p"); return err },
				func() error { _, err := c.Refresh(context.Background(), "p"); return err },
			} {
				err := call()
				if !errors.Is(err, tc.want) {
					t.Fatalf("got %v, want %v", err, tc.want)
				}
				var ae *client.APIError
				if !errors.As(err, &ae) || ae.Status != clienttestStatus(tc.e) {
					t.Fatalf("APIError %+v", ae)
				}
				d, ok := client.RetryAfter(err)
				if ok != (tc.retry > 0) || d != tc.retry {
					t.Fatalf("RetryAfter = %v %v", d, ok)
				}
				for _, other := range []error{client.ErrReauthRequired, client.ErrRevoked, client.ErrDegraded, client.ErrUnauthorized, client.ErrNotConfigured, client.ErrDaemonUnavailable} {
					if other != tc.want && errors.Is(err, other) {
						t.Fatalf("also matches %v", other)
					}
				}
			}
		})
	}
}

func clienttestStatus(e clienttest.Error) int {
	if e.HTTPStatus != 0 {
		return e.HTTPStatus
	}
	return map[string]int{"reauth_required": 401, "revoked": 403, "unauthorized": 403, "not_configured": 404, "degraded": 503}[e.Code]
}

func TestGlobalErrorAndStatusEndpoints(t *testing.T) {
	c, srv := newPair(t)
	srv.SetGlobalError(clienttest.Error{Code: clienttest.CodeRevoked, State: "revoked"})
	if _, err := c.Status(context.Background()); !errors.Is(err, client.ErrRevoked) {
		t.Fatal(err)
	}
	if _, err := c.Identity(context.Background()); !errors.Is(err, client.ErrRevoked) {
		t.Fatal(err)
	}
	var ae *client.APIError
	_, err := c.Status(context.Background())
	if !errors.As(err, &ae) || ae.State != client.StateRevoked || ae.Code != "revoked" || !strings.Contains(ae.Error(), "403 revoked") {
		t.Fatalf("%+v", ae)
	}
	srv.SetGlobalError(clienttest.Error{Code: clienttest.CodeDegraded, RetryAfter: 3 * time.Second})
	if _, err = c.Status(context.Background()); !strings.Contains(err.Error(), "retry after 3s") {
		t.Fatal(err)
	}
	srv.SetGlobalError(clienttest.Error{})
	if _, err := c.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestInternalErrorHasNoSentinel(t *testing.T) {
	c, srv := newPair(t)
	srv.SetProviderError("p", clienttest.Error{Code: clienttest.CodeInternal})
	_, err := c.Credential(context.Background(), "p")
	var ae *client.APIError
	if !errors.As(err, &ae) || ae.Status != 500 || errors.Is(err, client.ErrDegraded) || errors.Is(err, client.ErrDaemonUnavailable) {
		t.Fatalf("%v", err)
	}
	if _, ok := client.RetryAfter(err); ok {
		t.Fatal("unexpected retry hint")
	}
	if _, ok := client.RetryAfter(errors.New("x")); ok {
		t.Fatal("unexpected retry hint")
	}
	srv.SetProviderError("p", clienttest.Error{})
	if _, err := c.Credential(context.Background(), "p"); !errors.Is(err, client.ErrNotConfigured) {
		t.Fatal(err)
	}
}

func TestInvalidResponses(t *testing.T) {
	c, srv := newPair(t)
	srv.SetRaw(200, "not json")
	for _, call := range []func() error{
		func() error { _, err := c.Credential(context.Background(), "p"); return err },
		func() error { _, err := c.Status(context.Background()); return err },
	} {
		if err := call(); !errors.Is(err, client.ErrInvalidResponse) {
			t.Fatalf("got %v", err)
		}
	}
	srv.SetRaw(200, `{"token_type":"Bearer","access_token":""}`)
	if _, err := c.Credential(context.Background(), "p"); !errors.Is(err, client.ErrInvalidResponse) {
		t.Fatalf("empty token accepted: %v", err)
	}
	// A non-JSON error body still yields an APIError from the status.
	srv.SetRaw(503, "<html>")
	if _, err := c.Credential(context.Background(), "p"); !errors.Is(err, client.ErrDegraded) {
		t.Fatalf("got %v", err)
	}
	srv.SetRaw(0, "")
	srv.SetRaw(200, `{"access_token":5}`)
	if _, err := c.Credential(context.Background(), "p"); !errors.Is(err, client.ErrInvalidResponse) {
		t.Fatalf("got %v", err)
	}
}

func TestDaemonUnavailable(t *testing.T) {
	c := client.New(client.WithSocketPath(clienttest.DeadSocketPath(t)))
	_, err := c.Credential(context.Background(), "aws")
	if !errors.Is(err, client.ErrDaemonUnavailable) {
		t.Fatalf("got %v", err)
	}
	if errors.Is(err, client.ErrRevoked) {
		t.Fatal("must not look revoked")
	}
}

func TestDaemonStoppedMidSession(t *testing.T) {
	c, srv := newPair(t)
	srv.SetCredential("aws", cred)
	if _, err := c.Credential(context.Background(), "aws"); err != nil {
		t.Fatal(err)
	}
	srv.Close()
	srv.Close() // idempotent
	if _, err := c.Credential(context.Background(), "aws"); !errors.Is(err, client.ErrDaemonUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestTimeoutAndCancel(t *testing.T) {
	c, srv := newPair(t, client.WithTimeout(50*time.Millisecond))
	srv.SetCredential("aws", cred)
	srv.SetDelay(2 * time.Second)
	start := time.Now()
	_, err := c.Credential(context.Background(), "aws")
	if !errors.Is(err, client.ErrDaemonUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("timeout not honoured")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Credential(ctx, "aws"); !errors.Is(err, context.Canceled) || errors.Is(err, client.ErrDaemonUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestOptionsAndDefaults(t *testing.T) {
	t.Setenv(client.EnvSocket, "/tmp/env.sock")
	if got := client.New().SocketPath(); got != "/tmp/env.sock" {
		t.Fatalf("env: %q", got)
	}
	if got := client.New(client.WithSocketPath("/tmp/opt.sock")).SocketPath(); got != "/tmp/opt.sock" {
		t.Fatalf("option: %q", got)
	}
	t.Setenv(client.EnvSocket, "")
	if got := client.New().SocketPath(); got != client.DefaultSocketPath() || !strings.HasSuffix(got, "/agentd/agentd.sock") {
		t.Fatalf("default: %q", got)
	}
	if client.DefaultSocketPath() == "" {
		t.Fatal("empty default")
	}
	// WithTimeout ignores non-positive values.
	c, srv := newPair(t, client.WithTimeout(0), client.WithTimeout(-1))
	srv.SetCredential("aws", cred)
	if _, err := c.Credential(context.Background(), "aws"); err != nil {
		t.Fatal(err)
	}
	if client.DefaultTimeout != 5*time.Second {
		t.Fatal("default timeout changed")
	}
}

func TestSecretRedaction(t *testing.T) {
	s := client.NewSecret("hunter2")
	if s.Reveal() != "hunter2" || s.IsZero() || !client.NewSecret("").IsZero() {
		t.Fatal("basic")
	}
	var buf strings.Builder
	h := slog.New(slog.NewJSONHandler(&buf, nil))
	h.Info("x", "s", s, "c", client.Credential{AccessToken: s})
	out := fmt.Sprintf("%v|%+v|%#v|%s|%q|%d|%x", s, s, s, s, s, s, s) + buf.String()
	j, _ := s.MarshalJSON()
	tx, _ := s.MarshalText()
	out += string(j) + string(tx) + s.String() + s.GoString()
	if strings.Contains(out, "hunter2") || !strings.Contains(out, client.Redacted) {
		t.Fatalf("leak: %s", out)
	}
}

func TestSecretUnmarshal(t *testing.T) {
	var s client.Secret
	if err := s.UnmarshalJSON([]byte(`"abc"`)); err != nil || s.Reveal() != "abc" {
		t.Fatal(s, err)
	}
	if err := s.UnmarshalJSON([]byte(`5`)); err == nil {
		t.Fatal("expected error")
	}
}

func TestStateConstants(t *testing.T) {
	want := map[client.State]string{
		client.StateEmpty: "empty", client.StateMinting: "minting", client.StateValid: "valid",
		client.StateRefreshing: "refreshing", client.StateDegraded: "degraded", client.StateRevoked: "revoked",
		client.StateReauthRequired: "reauth_required",
	}
	for s, w := range want {
		if string(s) != w {
			t.Fatalf("%q != %q", s, w)
		}
	}
}

func TestConcurrentUse(t *testing.T) {
	c, srv := newPair(t)
	srv.SetCredential("aws", cred)
	errs := make(chan error, 20)
	for range 20 {
		go func() { _, err := c.Credential(context.Background(), "aws"); errs <- err }()
	}
	for range 20 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

// rawDaemon serves one canned HTTP response per connection on a unix socket.
func rawDaemon(t *testing.T, response string) *client.Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "aod")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "r.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = bufio.NewReader(conn).ReadString('\n')
				_, _ = conn.Write([]byte(response))
			}()
		}
	}()
	c := client.New(client.WithSocketPath(ln.Addr().String()))
	t.Cleanup(c.Close)
	return c
}

func TestRetryAfterHeaderFallback(t *testing.T) {
	c := rawDaemon(t, "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 9\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	_, err := c.Status(context.Background())
	if d, ok := client.RetryAfter(err); !ok || d != 9*time.Second || !errors.Is(err, client.ErrDegraded) {
		t.Fatalf("%v %v %v", d, ok, err)
	}
}

func TestTruncatedBody(t *testing.T) {
	c := rawDaemon(t, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{\"state\"")
	if _, err := c.Status(context.Background()); !errors.Is(err, client.ErrDaemonUnavailable) {
		t.Fatalf("got %v", err)
	}
}
