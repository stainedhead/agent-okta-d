package obs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/domain/domaintest"
)

const secretVal = "s3cr3t-token-value-XYZ"

func newLog(t *testing.T) (*slog.Logger, *bytes.Buffer, *domain.Scrubber) {
	t.Helper()
	sc := domain.NewScrubber()
	sc.Add(domain.NewSecret(secretVal))
	var buf bytes.Buffer
	return NewLogger(&buf, slog.LevelDebug, sc), &buf, sc
}

type stringer struct{ s string }

func (s stringer) String() string { return "str:" + s.s }

type panicky struct{}

func (panicky) String() string { panic("boom " + secretVal) }

type plain struct {
	A string
	B int
}

func TestLoggerRedactsEveryPath(t *testing.T) {
	log, buf, _ := newLog(t)
	log.Info("msg "+secretVal, "plain", "x"+secretVal, "err", errors.New("fail "+secretVal),
		"wrapped", fmt.Errorf("w: %w", errors.New(secretVal)),
		"stringer", stringer{secretVal}, "struct", plain{A: secretVal, B: 1},
		"ptr", &plain{A: secretVal}, "nilv", nil,
		"secretstr", domain.NewSecret(secretVal),
		slog.Group("g", "in", secretVal, slog.Group("h", "deep", secretVal)),
		"n", 5, "d", time.Second, "ok", true,
		secretVal, "keyed", "panicky", panicky{},
		"Authorization", "Bearer abc", "client_assertion", "zzz")
	log.With("pre", secretVal).WithGroup("grp"+secretVal).With("x", secretVal).Warn("again", "y", secretVal)
	out := buf.String()
	if strings.Contains(out, secretVal) {
		t.Fatalf("secret leaked:\n%s", out)
	}
	if strings.Contains(out, "Bearer abc") || strings.Contains(out, "zzz") {
		t.Fatalf("sensitive key value leaked:\n%s", out)
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not json: %v: %s", err, line)
		}
	}
}

func TestLoggerScrubsJWTWithoutRegistration(t *testing.T) {
	var buf bytes.Buffer
	log := NewLogger(&buf, slog.LevelInfo, nil)
	jwt := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sigsigsig"
	log.Info("got "+jwt, "v", jwt)
	log.Debug("hidden")
	if strings.Contains(buf.String(), "eyJ") || strings.Contains(buf.String(), "hidden") {
		t.Fatal(buf.String())
	}
}

func TestLoggerEnabledAndKeepsStructure(t *testing.T) {
	log, buf, _ := newLog(t)
	log.Info("hello", "n", 3, slog.Group("g", "a", "b"))
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["msg"] != "hello" || m["n"].(float64) != 3 || m["g"].(map[string]any)["a"] != "b" {
		t.Fatalf("%v", m)
	}
}

func TestGuardRedactsPanics(t *testing.T) {
	log, buf, sc := newLog(t)
	for _, v := range []any{"p " + secretVal, errors.New(secretVal), stringer{secretVal}, plain{A: secretVal}, panicky{}} {
		err := Guard(log, sc, func() error { panic(v) })
		if err == nil || !errors.Is(err, domain.ErrProvider) || strings.Contains(err.Error(), secretVal) {
			t.Fatalf("err = %v", err)
		}
	}
	if strings.Contains(buf.String(), secretVal) {
		t.Fatalf("panic log leaked:\n%s", buf.String())
	}
	want := errors.New("plain")
	if err := Guard(log, sc, func() error { return want }); err != want {
		t.Fatal(err)
	}
}

func TestGuardNilScrubber(t *testing.T) {
	log, _, _ := newLog(t)
	if err := Guard(log, nil, func() error { panic("x") }); err == nil {
		t.Fatal("want err")
	}
}

func TestAuditFieldsAndShape(t *testing.T) {
	clk := domaintest.NewFakeClock()
	var buf bytes.Buffer
	a := NewAudit(&buf, "agent-1", clk, nil)
	exp := clk.Now().Add(time.Hour)
	uid, pid := 1000, 42
	a.Emit(context.Background(), domain.AuditEvent{Event: domain.AuditServe, Provider: "snow", Audience: "aud",
		JTI: "j1", ExpiresAt: &exp, CallerUID: &uid, CallerPID: &pid, CallerExe: "/bin/snow", Result: domain.ResultOK})
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"ts", "agent_id", "event", "provider", "audience", "jti", "expires_at", "caller_uid", "caller_pid", "caller_exe", "result"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing %s in %v", k, m)
		}
	}
	if m["agent_id"] != "agent-1" || m["event"] != "serve" || !strings.HasSuffix(buf.String(), "}\n") {
		t.Fatalf("%v", m)
	}
	if _, ok := m["error_class"]; ok {
		t.Error("error_class should be omitted when empty")
	}
}

func TestAuditScrubsAndNeverFails(t *testing.T) {
	sc := domain.NewScrubber()
	sc.Add(domain.NewSecret(secretVal))
	var buf bytes.Buffer
	a := NewAudit(&buf, "a", nil, sc)
	a.Emit(context.Background(), domain.AuditEvent{Event: domain.AuditFailure, Detail: "x " + secretVal,
		CallerExe: "/" + secretVal, Provider: secretVal, Audience: secretVal, JTI: secretVal,
		AgentID: secretVal}.WithError(errors.New(secretVal)))
	if strings.Contains(buf.String(), secretVal) {
		t.Fatal(buf.String())
	}
	if a.Dropped() != 0 {
		t.Fatal("dropped")
	}
	// failing writer
	b := NewAudit(failWriter{}, "a", nil, nil)
	b.Emit(context.Background(), domain.AuditEvent{Event: domain.AuditStart})
	if b.Dropped() != 1 {
		t.Fatal("expected drop")
	}
	// marshal failure (NaN-free event cannot fail; use nil writer panic path)
	c := NewAudit(nil, "a", nil, nil)
	c.Emit(context.Background(), domain.AuditEvent{Event: domain.AuditStart})
	if c.Dropped() != 1 {
		t.Fatal("expected drop on panic")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestAuditConcurrentLinesStayWhole(t *testing.T) {
	var buf bytes.Buffer
	a := NewAudit(&buf, "a", domaintest.NewFakeClock(), nil)
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.Emit(context.Background(), domain.AuditEvent{Event: domain.AuditMint, Detail: fmt.Sprint(i), Result: domain.ResultOK})
		}()
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 50 {
		t.Fatalf("%d lines", len(lines))
	}
	for _, l := range lines {
		if !json.Valid([]byte(l)) {
			t.Fatalf("bad line %q", l)
		}
	}
}

// AC-008: no secret in any log or audit line, error path or recovered panic.
func FuzzNoSecretInOutput(f *testing.F) {
	for _, s := range []string{"abcdef", "tok_ABCDEF123456", "a b c d e f g", "eyJhbGciOi.eyJzdWIiOi.sig", "x\ny\tz\"q\\", "日本語日本語日本語"} {
		f.Add(s, s+"-pad")
	}
	f.Fuzz(func(t *testing.T, raw, other string) {
		// A secret is a random-looking token. Constrain to a realistic prefix so
		// the fuzzer cannot pick a substring of the log's own keys ("level").
		secret := "tok_" + raw
		if len(secret) < 6 || !isSafe(raw) {
			t.Skip()
		}
		sc := domain.NewScrubber()
		sc.Add(domain.NewSecret(secret))
		var lb, ab bytes.Buffer
		log := NewLogger(&lb, slog.LevelDebug, sc)
		aud := NewAudit(&ab, "agent", domaintest.NewFakeClock(), sc)
		e := errors.New("failed using " + secret + " " + other)
		log.Info("m "+secret+other, "a", secret, "e", e, "w", fmt.Errorf("wrap: %w", e),
			"s", stringer{secret}, "p", plain{A: secret}, "sec", domain.NewSecret(secret),
			slog.Group("g", "k", secret), secret, other)
		log.With("x", secret).WithGroup("q").Error("again", "e", e)
		_ = Guard(log, sc, func() error { panic(e) })
		_ = Guard(log, sc, func() error { panic(secret + other) })
		aud.Emit(context.Background(), domain.AuditEvent{Event: domain.AuditFailure, Detail: secret + other,
			CallerExe: secret, Provider: secret}.WithError(e))
		for name, out := range map[string]string{"log": lb.String(), "audit": ab.String()} {
			if strings.Contains(out, secret) {
				t.Fatalf("%s leaked %q:\n%s", name, secret, out)
			}
			enc, _ := json.Marshal(secret)
			if esc := string(enc[1 : len(enc)-1]); strings.Contains(out, esc) {
				t.Fatalf("%s leaked escaped %q:\n%s", name, esc, out)
			}
		}
	})
}

func isSafe(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '\ufffd' {
			return false
		}
	}
	return true
}

type memStore struct {
	val domain.SecretString
	err error
}

func (m *memStore) Get(context.Context, string) (domain.SecretValue, error) {
	return domain.SecretValue{Value: m.val, Version: "1"}, m.err
}

func (m *memStore) Put(_ context.Context, _ string, v domain.SecretString, _ string) (string, error) {
	m.val = v
	return "2", m.err
}

func TestScrubStoreRegistersReadAndRotatedValues(t *testing.T) {
	sc := domain.NewScrubber()
	ms := &memStore{val: domain.NewSecret("old-refresh-token-AAAA")}
	st := ScrubStore(ms, sc)
	if _, err := st.Get(context.Background(), "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put(context.Background(), "k", domain.NewSecret("new-refresh-token-BBBB"), "1"); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"old-refresh-token-AAAA", "new-refresh-token-BBBB"} {
		if got := sc.Scrub("err: " + v); strings.Contains(got, v) {
			t.Errorf("%s leaked: %q", v, got)
		}
	}
	// error path: failed read registers nothing, failed write still does
	ms.err = errors.New("boom")
	sc2 := domain.NewScrubber()
	st2 := ScrubStore(ms, sc2)
	ms.val = domain.NewSecret("unread-value-CCCC")
	_, _ = st2.Get(context.Background(), "k")
	if sc2.Scrub("unread-value-CCCC") != "unread-value-CCCC" {
		t.Error("failed read registered a value")
	}
	_, _ = st2.Put(context.Background(), "k", domain.NewSecret("failed-write-DDDD"), "")
	if sc2.Scrub("failed-write-DDDD") == "failed-write-DDDD" {
		t.Error("failed write not registered")
	}
	if ScrubStore(ms, nil) != domain.SecretStore(ms) || ScrubStore(nil, sc) != nil {
		t.Error("nil passthrough")
	}
}
