package app

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/pkg/client"
)

// TestEndToEnd is P2.9: the daemon with a fake Okta (httptest), a fake clock
// and pkg/client over a real unix socket.
func TestEndToEnd(t *testing.T) {
	f := newFixture(t, fixOpt{})
	d, sigs, _, done := f.start(t)
	_ = d
	c := f.client()
	ctx := context.Background()

	// Cold call mints through the fake Okta and writes the token file (AWS-1).
	cred, err := c.Credential(ctx, "aws")
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessToken.IsZero() || cred.Audience != "sts.amazonaws.com" || cred.TokenType != "aws-web-identity" {
		t.Fatalf("unexpected credential %v", cred)
	}
	if got, want := cred.ExpiresAt.Sub(cred.IssuedAt), time.Hour; got != want {
		t.Fatalf("ttl %v, want %v (taken from the Okta response)", got, want)
	}
	tokenFile := f.cfg.Providers.AWS.TokenFile
	b, err := os.ReadFile(tokenFile)
	if err != nil || string(b) != cred.AccessToken.Reveal() {
		t.Fatalf("token file mismatch: %v", err)
	}
	if fi, _ := os.Stat(tokenFile); fi.Mode().Perm() != 0o440 {
		t.Fatalf("token file mode %v, want 0440", fi.Mode().Perm())
	}
	calls := f.w.calls()

	// Cached: no new Okta call and well under 10 ms (best of N, warm connection).
	best := time.Hour
	for range 30 {
		start := time.Now()
		again, err := c.Credential(ctx, "aws")
		el := time.Since(start)
		if err != nil {
			t.Fatal(err)
		}
		if again.AccessToken.Reveal() != cred.AccessToken.Reveal() {
			t.Fatal("cached credential changed")
		}
		best = min(best, el)
	}
	if best >= 10*time.Millisecond {
		t.Fatalf("cached token took %v, want < 10ms", best)
	}
	if f.w.calls() != calls {
		t.Fatalf("cached calls hit Okta: %d -> %d", calls, f.w.calls())
	}

	// Second provider, status and identity.
	snow, err := c.Credential(ctx, "servicenow")
	if err != nil || snow.TokenType != "Bearer" {
		t.Fatalf("servicenow: %v %v", snow, err)
	}
	st, err := c.Status(ctx)
	if err != nil || st.State != client.StateValid || len(st.Providers) != 2 {
		t.Fatalf("status: %+v %v", st, err)
	}
	id, err := c.Identity(ctx)
	if err != nil || id.AgentID != "agent-1" || id.KID != "kid-1" || id.OktaClientID != "0oaTEST" || id.APIVersion != "v1" {
		t.Fatalf("identity: %+v %v", id, err)
	}

	// Forced refresh mints again.
	if _, err := c.Refresh(ctx, "aws"); err != nil {
		t.Fatal(err)
	}
	if f.w.calls() <= calls {
		t.Fatal("refresh did not reach Okta")
	}

	// Unknown provider is 404 not_configured.
	if _, err := c.Credential(ctx, "nope"); !errors.Is(err, client.ErrNotConfigured) {
		t.Fatalf("want ErrNotConfigured, got %v", err)
	}

	// Revoke by signal: 403 path, files gone, exit 77, socket closed.
	sigs <- syscall.SIGUSR1
	err = waitErr(t, done)
	if code := exitCode(err); code != 77 {
		t.Fatalf("exit code %d (err %v), want 77", code, err)
	}
	if _, err := os.Stat(tokenFile); !os.IsNotExist(err) {
		t.Fatalf("token file survives revoke: %v", err)
	}
	if _, err := os.Stat(PidFile(f.cfg)); !os.IsNotExist(err) {
		t.Fatal("pidfile survives revoke")
	}
	if _, err := c.Credential(ctx, "aws"); !errors.Is(err, client.ErrDaemonUnavailable) {
		t.Fatalf("want ErrDaemonUnavailable after exit, got %v", err)
	}
	if strings.Contains(f.stderr.String(), cred.AccessToken.Reveal()) {
		t.Fatal("token leaked into the log")
	}
}

func TestGracefulStop(t *testing.T) {
	f := newFixture(t, fixOpt{})
	_, sigs, _, done := f.start(t)
	if _, err := f.client().Credential(context.Background(), "aws"); err != nil {
		t.Fatal(err)
	}
	sigs <- syscall.SIGHUP // logged, ignored
	sigs <- syscall.SIGTERM
	if err := waitErr(t, done); err != nil {
		t.Fatalf("graceful stop: %v", err)
	}
	if _, err := os.Stat(f.cfg.Providers.AWS.TokenFile); !os.IsNotExist(err) {
		t.Fatal("token file survives stop")
	}
	if !strings.Contains(f.stderr.String(), "SIGHUP ignored") {
		t.Fatal("SIGHUP not logged")
	}
}

func TestContextCancelStops(t *testing.T) {
	f := newFixture(t, fixOpt{})
	_, _, cancel, done := f.start(t)
	cancel()
	if err := waitErr(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestAutomaticRevoke(t *testing.T) {
	f := newFixture(t, fixOpt{})
	d, _, _, done := f.start(t)
	if _, err := f.client().Credential(context.Background(), "aws"); err != nil {
		t.Fatal(err)
	}
	d.Cache().Revoke(context.Background()) // what two definitive errors do
	err := waitErr(t, done)
	if exitCode(err) != 77 || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(f.stderr.String(), "CRITICAL withdraw complete") {
		t.Fatalf("no critical audit event: %s", f.stderr.String())
	}
}

// TestRevokeSequence is AC-009: the six steps run in order, proven with a
// shared log across the sink, the provider and the audit stream.
func TestRevokeSequence(t *testing.T) {
	f := newFixture(t, fixOpt{})
	var (
		omu   sync.Mutex
		order []string
	)
	rec := func(s string) {
		omu.Lock()
		order = append(order, s)
		omu.Unlock()
	}
	var d *Daemon
	f.env.Sink = recSink{Sink: f.env.Sink, rec: func(op, path string) {
		state := ""
		if d != nil {
			if e, ok := d.Cache().Entry("aws"); ok {
				state = string(e.State)
			}
		}
		rec(op + ":" + state)
	}}
	f.stderr.hit = func(line string) {
		switch {
		case strings.Contains(line, `"event":"revoke"`) && strings.Contains(line, "CRITICAL"):
			rec("audit-critical")
		case strings.Contains(line, `"event":"revoke"`):
			rec("audit-revoke")
		}
	}
	var sigs chan os.Signal
	var done chan error
	d, sigs, _, done = f.start(t)
	if _, err := f.client().Credential(context.Background(), "aws"); err != nil {
		t.Fatal(err)
	}
	sigs <- syscall.SIGUSR1
	if err := waitErr(t, done); exitCode(err) != 77 {
		t.Fatalf("got %v", err)
	}
	omu.Lock()
	got := slices.Clone(order)
	omu.Unlock()
	// Step 1: the state is revoked before any file is touched (so every caller
	// already gets 403); steps 2 and 3: files removed; step 5 last.
	iRev := slices.Index(got, "audit-revoke")
	iRemove := slices.Index(got, "remove:revoked")
	iCrit := slices.Index(got, "audit-critical")
	if iRev < 0 || iRemove < 0 || iCrit < 0 || iRev >= iRemove || iRemove >= iCrit {
		t.Fatalf("order wrong: %v", got)
	}
	if slices.Contains(got, "remove:valid") || slices.Contains(got, "remove:refreshing") {
		t.Fatalf("a file was removed before the state turned revoked: %v", got)
	}
	if iCrit != len(got)-1 {
		t.Fatalf("critical audit event is not last: %v", got)
	}
}
