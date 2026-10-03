package app

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/config"
	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/domain/domaintest"
	awsprov "github.com/stainedhead/agent-okta-d/internal/provider/aws"
	"github.com/stainedhead/agent-okta-d/pkg/client"
)

type fakeSTS struct {
	arn string
	err error
}

func (s fakeSTS) GetCallerIdentity(context.Context, string, string, domain.SecretString) (awsprov.Identity, error) {
	return awsprov.Identity{ARN: s.arn}, s.err
}

const goodARN = "arn:aws:sts::222222222222:assumed-role/agent-x/agent-1"

func runErr(t *testing.T, f *fixture, reg *Registry) error {
	t.Helper()
	d, err := New(f.cfg, f.env, reg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return d.Run(ctx, make(chan os.Signal))
}

func fakeRegistry(ps ...domain.Provider) *Registry {
	r := NewRegistry()
	for _, p := range ps {
		r.Register(p.Name(), func(*config.Config, Env) (*Registered, error) {
			return &Registered{Provider: p, Key: domain.Key{Provider: p.Name()}}, nil
		})
	}
	return r
}

func TestRunRefusesAgentGroup(t *testing.T) {
	f := newFixture(t, fixOpt{})
	f.env.Host = fakeHost{euid: 1001, gid: os.Getgid(), pid: 1}
	err := runErr(t, f, DefaultRegistry())
	if !errors.Is(err, domain.ErrPolicy) || !strings.Contains(err.Error(), "allow_gids") {
		t.Fatalf("got %v", err)
	}
	if _, serr := os.Stat(f.cfg.IPC.Socket); serr == nil {
		t.Fatal("socket created despite policy failure")
	}
}

func TestStartupDefinitiveOktaRejectionExits77(t *testing.T) {
	f := newFixture(t, fixOpt{})
	f.w.set(func(w *world) { w.oktaStatus, w.oktaCode = 401, "invalid_client" })
	err := runErr(t, f, DefaultRegistry())
	if exitCode(err) != domain.ExitRevoked || !errors.Is(err, domain.ErrAuthDefinitive) {
		t.Fatalf("got %v (exit %d)", err, exitCode(err))
	}
}

func TestStartupClockSkewIsFatal(t *testing.T) {
	f := newFixture(t, fixOpt{})
	f.w.set(func(w *world) { w.skew = 2 * time.Minute })
	err := runErr(t, f, DefaultRegistry())
	if err == nil || !strings.Contains(err.Error(), "clock skew") || exitCode(err) != 1 {
		t.Fatalf("got %v", err)
	}
}

func TestStartupTransientOktaKeepsProvidersDegraded(t *testing.T) {
	f := newFixture(t, fixOpt{})
	f.w.set(func(w *world) { w.oktaStatus, w.oktaCode = 503, "server_error" })
	_, _, _, _ = f.start(t)
	_, err := f.client().Credential(context.Background(), "aws")
	if !errors.Is(err, client.ErrDegraded) {
		t.Fatalf("want degraded, got %v", err)
	}
	if _, ok := client.RetryAfter(err); !ok {
		t.Fatal("degraded answer lacks a Retry-After hint")
	}
	if !strings.Contains(f.stderr.String(), "transient, will retry") {
		t.Fatal("self-test did not warn about the transient error")
	}
}

func TestSelfTestRefusesBrokenProvider(t *testing.T) {
	f := newFixture(t, fixOpt{})
	good := &domaintest.FakeProvider{ProviderName: "good"}
	bad := &domaintest.FakeProvider{ProviderName: "bad", MintFn: func(context.Context, domain.Deps) (domain.Credential, error) {
		return domain.Credential{}, domain.NewConfigError("bad", "broken")
	}}
	reauth := &domaintest.FakeProvider{ProviderName: "reauth", MintFn: func(context.Context, domain.Deps) (domain.Credential, error) {
		return domain.Credential{}, domain.ErrReauthRequired
	}}
	panics := &domaintest.FakeProvider{ProviderName: "panics", MintFn: func(context.Context, domain.Deps) (domain.Credential, error) {
		panic("boom")
	}}
	d, err := New(f.cfg, f.env, fakeRegistry(good, bad, reauth, panics))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx, make(chan os.Signal)) }()
	for range 200 {
		if _, err := os.Stat(PidFile(f.cfg)); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	c := f.client()
	if _, err := c.Credential(ctx, "good"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Credential(ctx, "bad"); !errors.Is(err, client.ErrNotConfigured) {
		t.Fatalf("refused provider must answer 404, got %v", err)
	}
	if _, err := c.Credential(ctx, "panics"); !errors.Is(err, client.ErrNotConfigured) {
		t.Fatalf("panicking provider must be refused, got %v", err)
	}
	if _, err := c.Credential(ctx, "reauth"); !errors.Is(err, client.ErrReauthRequired) {
		t.Fatalf("want reauth_required, got %v", err)
	}
	cancel()
	<-done
}

func TestStartupNoProviders(t *testing.T) {
	f := newFixture(t, fixOpt{})
	err := runErr(t, f, NewRegistry())
	if !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("got %v", err)
	}
	bad := &domaintest.FakeProvider{ProviderName: "bad", MintFn: func(context.Context, domain.Deps) (domain.Credential, error) {
		return domain.Credential{}, domain.Wrap(domain.ErrProvider, errors.New("nope"))
	}}
	err = runErr(t, f, fakeRegistry(bad))
	if !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("got %v", err)
	}
}

func TestStartupWipesStaleSinks(t *testing.T) {
	f := newFixture(t, fixOpt{})
	tf := f.cfg.Providers.AWS.TokenFile
	stale := filepath.Join(filepath.Dir(tf), ".aws.jwt.okta-d-tmp-123")
	for _, p := range []string{tf, stale} {
		if err := os.WriteFile(p, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f.start(t)
	for _, p := range []string{tf, stale} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s survives start: %v", p, err)
		}
	}
}

func TestStartupSocketGroupNotMember(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can chown to any group")
	}
	f := newFixture(t, fixOpt{allow: "1"}) // gid 1 (daemon) exists, but we are not in it
	err := runErr(t, f, DefaultRegistry())
	if !errors.Is(err, domain.ErrPolicy) {
		t.Fatalf("got %v", err)
	}
}

func TestMultipleAllowGIDsOpensSocketMode(t *testing.T) {
	f := newFixture(t, fixOpt{allow: "agents, 4000"})
	f.start(t)
	fi, err := os.Stat(f.cfg.IPC.Socket)
	if err != nil || fi.Mode().Perm() != 0o666 {
		t.Fatalf("socket mode %v err %v", fi.Mode(), err)
	}
	if _, err := f.client().Status(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNewErrors(t *testing.T) {
	cases := map[string]fixOpt{
		"kms without adapter": {signer: "{type: kms, key_id: arn:x, alg: RS256, kid: k}"},
		"keychain":            {signer: "{type: keychain, alg: RS256, kid: k}"},
		"tpm":                 {signer: "{type: tpm, alg: RS256, kid: k}"},
		"unknown group":       {allow: "nogroup"},
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, o)
			_, err := New(f.cfg, f.env, DefaultRegistry())
			if !errors.Is(err, domain.ErrConfig) {
				t.Fatalf("got %v", err)
			}
		})
	}
	t.Run("kms adapter error", func(t *testing.T) {
		f := newFixture(t, fixOpt{signer: "{type: kms, key_id: arn:x, alg: RS256, kid: k}"})
		f.env.KMS = nil
		if _, err := NewSigner(f.cfg, f.env); !errors.Is(err, domain.ErrConfig) {
			t.Fatal(err)
		}
	})
	t.Run("world readable key", func(t *testing.T) {
		f := newFixture(t, fixOpt{})
		if err := os.Chmod(f.cfg.Okta.Signer.KeyID, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := New(f.cfg, f.env, DefaultRegistry()); !errors.Is(err, domain.ErrPolicy) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("alg mismatch", func(t *testing.T) {
		f := newFixture(t, fixOpt{})
		f.cfg.Okta.Signer.Alg = "ES256"
		if _, err := New(f.cfg, f.env, DefaultRegistry()); !errors.Is(err, domain.ErrConfig) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("unknown signer type", func(t *testing.T) {
		f := newFixture(t, fixOpt{})
		f.cfg.Okta.Signer.Type = "other"
		if _, err := NewSigner(f.cfg, f.env); !errors.Is(err, domain.ErrConfig) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad log destination", func(t *testing.T) {
		f := newFixture(t, fixOpt{})
		f.cfg.Log.Destination = "relative/path"
		if _, err := New(f.cfg, f.env, DefaultRegistry()); !errors.Is(err, domain.ErrConfig) {
			t.Fatalf("got %v", err)
		}
		f.cfg.Log.Destination = filepath.Join(f.dir, "missing", "x.log")
		if _, err := New(f.cfg, f.env, DefaultRegistry()); !errors.Is(err, domain.ErrConfig) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad log level", func(t *testing.T) {
		f := newFixture(t, fixOpt{})
		f.cfg.Log.Level = "loud"
		if _, err := New(f.cfg, f.env, DefaultRegistry()); !errors.Is(err, domain.ErrConfig) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad okta org", func(t *testing.T) {
		f := newFixture(t, fixOpt{})
		f.cfg.Okta.OrgURL = "ftp://x"
		if _, err := New(f.cfg, f.env, DefaultRegistry()); !errors.Is(err, domain.ErrConfig) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("provider build error", func(t *testing.T) {
		f := newFixture(t, fixOpt{})
		f.cfg.Providers.AWS.RoleARN = "bogus"
		if _, err := New(f.cfg, f.env, DefaultRegistry()); !errors.Is(err, domain.ErrConfig) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad cache config", func(t *testing.T) {
		f := newFixture(t, fixOpt{})
		f.cfg.Refresh.Jitter = 0.9
		if _, err := New(f.cfg, f.env, DefaultRegistry()); !errors.Is(err, domain.ErrConfig) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestLogToFileAndStdout(t *testing.T) {
	f := newFixture(t, fixOpt{})
	f.cfg.Log.Destination = filepath.Join(f.dir, "d.log")
	d, err := New(f.cfg, f.env, DefaultRegistry())
	if err != nil {
		t.Fatal(err)
	}
	d.log.Info("hello")
	d.Close()
	if b, _ := os.ReadFile(f.cfg.Log.Destination); !strings.Contains(string(b), "hello") {
		t.Fatalf("log file: %q", b)
	}
	f.cfg.Log.Destination = "stdout"
	d, err = New(f.cfg, f.env, DefaultRegistry())
	if err != nil {
		t.Fatal(err)
	}
	d.log.Info("to-stdout")
	if !strings.Contains(f.stdout.String(), "to-stdout") {
		t.Fatal("stdout destination not used")
	}
}

func TestDoctor(t *testing.T) {
	f := newFixture(t, fixOpt{})
	f.env.STS = fakeSTS{arn: goodARN}
	d, err := New(f.cfg, f.env, DefaultRegistry())
	if err != nil {
		t.Fatal(err)
	}
	rep := d.Doctor(context.Background())
	if rep.Failed() {
		var sb strings.Builder
		rep.Write(&sb)
		t.Fatalf("doctor failed:\n%s", sb.String())
	}
	var sb strings.Builder
	rep.Write(&sb)
	for _, want := range []string{"user-separation", "okta-clock-skew", "provider:aws:probe", "provider:servicenow:probe", "signer"} {
		if !strings.Contains(sb.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, sb.String())
		}
	}
}

func TestDoctorFailures(t *testing.T) {
	t.Run("no sts adapter fails aws probe", func(t *testing.T) {
		f := newFixture(t, fixOpt{})
		d, _ := New(f.cfg, f.env, DefaultRegistry())
		rep := d.Doctor(context.Background())
		if !rep.Failed() {
			t.Fatal("doctor should fail without an STS client")
		}
	})
	t.Run("wrong role session", func(t *testing.T) {
		f := newFixture(t, fixOpt{})
		f.env.STS = fakeSTS{arn: "arn:aws:sts::1:assumed-role/other/x"}
		d, _ := New(f.cfg, f.env, DefaultRegistry())
		if !d.Doctor(context.Background()).Failed() {
			t.Fatal("want failure")
		}
	})
	t.Run("servicenow disabled user", func(t *testing.T) {
		f := newFixture(t, fixOpt{})
		f.env.STS = fakeSTS{arn: goodARN}
		f.w.set(func(w *world) { w.snowStatus = 403 })
		d, _ := New(f.cfg, f.env, DefaultRegistry())
		if !d.Doctor(context.Background()).Failed() {
			t.Fatal("want failure")
		}
	})
	t.Run("agent group is a fatal separation failure", func(t *testing.T) {
		f := newFixture(t, fixOpt{})
		f.env.Host = fakeHost{euid: 0, gid: os.Getgid()}
		d, _ := New(f.cfg, f.env, DefaultRegistry())
		rep := d.Doctor(context.Background())
		if !rep.Failed() || rep.Checks[len(rep.Checks)-1].Name != "abort" {
			t.Fatalf("%+v", rep.Checks)
		}
	})
	t.Run("root only warns", func(t *testing.T) {
		f := newFixture(t, fixOpt{})
		f.env.STS = fakeSTS{arn: goodARN}
		f.env.Host = fakeHost{euid: 0, gid: 99999}
		d, _ := New(f.cfg, f.env, DefaultRegistry())
		rep := d.Doctor(context.Background())
		var warned bool
		for _, c := range rep.Checks {
			warned = warned || (c.Name == "user-separation" && c.Status == StatusWarn)
		}
		if !warned || rep.Failed() {
			t.Fatalf("%+v", rep.Checks)
		}
	})
	t.Run("signer failure", func(t *testing.T) {
		f := newFixture(t, fixOpt{})
		d, _ := New(f.cfg, f.env, DefaultRegistry())
		d.signer = &domaintest.FakeSigner{Err: errors.New("hsm gone")}
		if rep := d.Doctor(context.Background()); !rep.Failed() {
			t.Fatal("want failure")
		}
	})
	t.Run("definitive okta rejection", func(t *testing.T) {
		f := newFixture(t, fixOpt{})
		f.w.set(func(w *world) { w.oktaStatus, w.oktaCode = 400, "invalid_client" })
		d, _ := New(f.cfg, f.env, DefaultRegistry())
		if rep := d.Doctor(context.Background()); !rep.Failed() {
			t.Fatal("want failure")
		}
	})
	t.Run("skew transient is only a warning", func(t *testing.T) {
		f := newFixture(t, fixOpt{})
		f.env.STS = fakeSTS{arn: goodARN}
		f.env.HTTP = &http.Client{Transport: failingFirstHead{redirect{f.w}, new(bool)}}
		d, _ := New(f.cfg, f.env, DefaultRegistry())
		rep, fatal := d.SelfTest(context.Background())
		if fatal != nil {
			t.Fatal(fatal)
		}
		var warned bool
		for _, c := range rep.Checks {
			warned = warned || (c.Name == "okta-clock-skew" && c.Status == StatusWarn)
		}
		if !warned {
			t.Fatalf("%+v", rep.Checks)
		}
	})
}

// failingFirstHead fails the first HEAD request (the skew probe).
type failingFirstHead struct {
	next http.RoundTripper
	done *bool
}

func (f failingFirstHead) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodHead && !*f.done {
		*f.done = true
		return nil, errors.New("network down")
	}
	return f.next.RoundTrip(r)
}
