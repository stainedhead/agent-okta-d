package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/cache"
	"github.com/stainedhead/agent-okta-d/internal/config"
	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/domain/domaintest"
	"github.com/stainedhead/agent-okta-d/internal/obs"
	"github.com/stainedhead/agent-okta-d/internal/signer/kms"
	"github.com/stainedhead/agent-okta-d/internal/store/awssm"
)

// fakeSM is an in-memory Secrets Manager.
type fakeSM struct{ vals map[string]string }

func (f fakeSM) GetSecretValue(_ context.Context, id string) (awssm.SecretVersion, error) {
	v, ok := f.vals[id]
	if !ok {
		return awssm.SecretVersion{}, awssm.ErrResourceNotFound
	}
	return awssm.SecretVersion{Value: v, VersionID: "v1"}, nil
}

func (f fakeSM) CreateSecret(context.Context, string, string, string) (string, error) {
	return "", errors.New("unused")
}

func (f fakeSM) PutSecretValue(context.Context, string, string, string, []string) (string, error) {
	return "", errors.New("unused")
}
func (f fakeSM) MoveCurrent(context.Context, string, string, string) error {
	return errors.New("unused")
}

func TestAtlassianSecretProviderServes(t *testing.T) {
	f := newFixture(t, fixOpt{})
	dir := f.dir
	prov := `  atlassian:
    source: aws-secretsmanager
    secret_id: atl-secret
    sink: {file: ` + dir + `/atl.key, mode: "0440"}
    interval_seconds: 60`
	g := newFixture(t, fixOpt{providers: prov})
	g.env.SecretsManager = func(*config.Config) (awssm.SecretsManagerAPI, error) {
		return fakeSM{vals: map[string]string{"atl-secret": "atl-api-key-0123456789"}}, nil
	}
	g.cfg.Providers.Atlassian.Sink.File = filepath.Join(g.dir, "atl.key")
	g.start(t)
	cred, err := g.client().Credential(context.Background(), "atlassian")
	if err != nil || cred.AccessToken.Reveal() != "atl-api-key-0123456789" {
		t.Fatalf("%v %v", cred, err)
	}
	b, err := os.ReadFile(g.cfg.Providers.Atlassian.Sink.File)
	if err != nil || string(b) != "atl-api-key-0123456789" {
		t.Fatalf("sink file %q %v", b, err)
	}
	if fi, _ := os.Stat(g.cfg.Providers.Atlassian.Sink.File); fi.Mode().Perm() != 0o440 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if strings.Contains(g.stderr.String(), "atl-api-key-0123456789") {
		t.Fatal("secret leaked into the log")
	}
}

func TestStoresBuild(t *testing.T) {
	f := newFixture(t, fixOpt{})
	d, err := New(f.cfg, f.env, DefaultRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.deps.Store("nope"); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("unknown store: %v", err)
	}
	if _, err := d.deps.Store(StoreAWSSecretsManager); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("no SM adapter: %v", err)
	}
	f.env.SecretsManager = func(*config.Config) (awssm.SecretsManagerAPI, error) { return nil, errors.New("creds") }
	d, _ = New(f.cfg, f.env, DefaultRegistry())
	if _, err := d.deps.Store(StoreAWSSecretsManager); err == nil {
		t.Fatal("adapter error must surface")
	}
	f.env.SecretsManager = func(*config.Config) (awssm.SecretsManagerAPI, error) { return fakeSM{}, nil }
	d, _ = New(f.cfg, f.env, DefaultRegistry())
	s1, err := d.deps.Store(StoreAWSSecretsManager)
	s2, _ := d.deps.Store(StoreAWSSecretsManager)
	if err != nil || s1 != s2 {
		t.Fatalf("store must be built once: %v", err)
	}
	if _, err := d.deps.Store(StoreKeychain); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("native keychain is a stub in this build: %v", err)
	}
	if !strings.HasPrefix(d.deps.stores.encPath(), "/var/") {
		t.Fatalf("default state dir: %s", d.deps.stores.encPath())
	}
	// file-encrypted works with RS256 and refuses ES256.
	g := newFixture(t, fixOpt{providers: githubProviders("PLACEHOLDER", "pat")})
	g.cfgp = rewriteStorePath(t, g)
	d, err = New(g.cfg, g.env, DefaultRegistry())
	if err != nil {
		t.Fatal(err)
	}
	st, err := d.deps.Store(StoreFileEncrypted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put(context.Background(), "k", domain.NewSecret("v-0123456789"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := (signerKey{d.signer, "ES256"}).Key(context.Background()); !errors.Is(err, domain.ErrConfig) {
		t.Fatal("ES256 must be refused")
	}
	if _, err := (signerKey{&domaintest.FakeSigner{Err: errors.New("x")}, "RS256"}).Key(context.Background()); err == nil {
		t.Fatal("signer error must surface")
	}
}

type fakeKMS struct{}

func (fakeKMS) SignDigest(context.Context, string, []byte, string) ([]byte, error) {
	return nil, errors.New("unused")
}
func (fakeKMS) PublicKeyDER(context.Context, string) ([]byte, error) {
	return nil, errors.New("unused")
}

func TestKMSSignerSelection(t *testing.T) {
	f := newFixture(t, fixOpt{signer: "{type: kms, key_id: arn:k, alg: RS256, kid: k1}"})
	f.env.KMS = func(id string) (kms.KMSAPI, error) {
		if id != "arn:k" {
			t.Errorf("key id %q", id)
		}
		return fakeKMS{}, nil
	}
	s, err := NewSigner(f.cfg, f.env)
	if err != nil || s == nil {
		t.Fatalf("%v", err)
	}
	f.env.KMS = func(string) (kms.KMSAPI, error) { return nil, errors.New("no creds") }
	if _, err := NewSigner(f.cfg, f.env); err == nil {
		t.Fatal("want error")
	}
}

func TestRegistry(t *testing.T) {
	r := DefaultRegistry()
	if got := strings.Join(r.Types(), ","); got != "aws,github,servicenow,msgraph,secret" {
		t.Fatalf("types %s", got)
	}
	f := newFixture(t, fixOpt{providers: defaultProviders("/x", "https://x.example")})
	f.cfg.Okta.AuthorizationServers = map[string]config.AuthServer{"agents-aws": {ID: "aus9", Audience: "aud9"}}
	regs, err := r.Build(f.cfg, f.env)
	if err != nil || len(regs) != 2 {
		t.Fatalf("%v %d", err, len(regs))
	}
	as := regs[0].OktaServers["agents-aws"]
	if as.ID != "aus9" || as.Audience != "aud9" {
		t.Fatalf("override: %+v", as)
	}
	if regs[0].Options.Fraction != 0.45 || regs[1].Options.MinTTL != 120*time.Second {
		t.Fatalf("options: %+v %+v", regs[0].Options, regs[1].Options)
	}
	if got := authServer(f.cfg, "plain", "a")["plain"]; got.ID != "plain" || got.Audience != "a" {
		t.Fatalf("fallback: %+v", got)
	}
	if !strings.Contains(stateDir("a1"), "a1") {
		t.Fatal("stateDir")
	}
	if _, ok := parseMode("0440"); !ok {
		t.Fatal("0440")
	}
	for _, bad := range []string{"", "9", "07777"} {
		if _, ok := parseMode(bad); ok {
			t.Fatalf("%q accepted", bad)
		}
	}
	f.cfg.Providers.Atlassian = &config.Atlassian{Source: "aws-secretsmanager", SecretID: "x", Sink: config.Sink{File: "/x/a", Mode: "bogus"}}
	if _, err := r.Build(f.cfg, f.env); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("bad atlassian mode: %v", err)
	}
	f.cfg.Providers.Atlassian.Sink.Mode = "0440"
	f.cfg.Providers.Atlassian.SecretID = ""
	if _, err := r.Build(f.cfg, f.env); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("bad atlassian: %v", err)
	}
	// a named group becomes the sink group
	f.cfg.IPC.AllowGIDs = []string{"123", "agents"}
	if sinkGroup(f.cfg) != "agents" {
		t.Fatal("sink group")
	}
}

func TestRevokeCommand(t *testing.T) {
	f := newFixture(t, fixOpt{})
	tf := f.cfg.Providers.AWS.TokenFile
	pidf := PidFile(f.cfg)
	write := func() {
		if err := os.WriteFile(tf, []byte("tok"), 0o440); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("no daemon wipes files", func(t *testing.T) {
		write()
		if c := f.main("revoke"); c != 0 || !strings.Contains(f.stdout.String(), "no running daemon") {
			t.Fatalf("%d %q", c, f.stdout.String())
		}
		if _, err := os.Stat(tf); !os.IsNotExist(err) {
			t.Fatal("token file not removed")
		}
	})
	t.Run("signals a live daemon and waits", func(t *testing.T) {
		write()
		if err := os.WriteFile(pidf, []byte("4321\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		alive, sleeps := true, 0
		var sent os.Signal
		f.env.Alive = func(int) bool { return alive }
		f.env.Signal = func(pid int, s os.Signal) error {
			if pid != 4321 {
				t.Errorf("pid %d", pid)
			}
			sent = s
			return nil
		}
		f.env.Sleep = func(time.Duration) {
			sleeps++
			if sleeps == 3 {
				alive = false
			}
		}
		if c := f.main("revoke"); c != 0 || sent != syscall.SIGUSR1 || sleeps != 3 {
			t.Fatalf("%d sent=%v sleeps=%d %s", c, sent, sleeps, f.stderr.String())
		}
	})
	t.Run("daemon that will not die is an error but files are wiped", func(t *testing.T) {
		write()
		f.env.Alive = func(int) bool { return true }
		if c := f.main("revoke", "--timeout", "300ms"); c != 1 {
			t.Fatalf("got %d", c)
		}
		if _, err := os.Stat(tf); !os.IsNotExist(err) {
			t.Fatal("files must be wiped even when the daemon is stuck")
		}
	})
	t.Run("signal failure", func(t *testing.T) {
		f.env.Alive = func(int) bool { return true }
		f.env.Signal = func(int, os.Signal) error { return errors.New("EPERM") }
		if c := f.main("revoke"); c != 1 {
			t.Fatalf("got %d", c)
		}
	})
	t.Run("malformed pidfile", func(t *testing.T) {
		_ = os.WriteFile(pidf, []byte("zzz"), 0o644)
		if c := f.main("revoke"); c != 1 {
			t.Fatalf("got %d", c)
		}
	})
	t.Run("provider config error", func(t *testing.T) {
		_ = os.Remove(pidf)
		f.cfg.Providers.AWS.RoleARN = "bogus"
		if err := Revoke(context.Background(), f.cfg, f.env, time.Second); !errors.Is(err, domain.ErrConfig) {
			t.Fatalf("got %v", err)
		}
	})
	if c := f.mainNoCfg("revoke", "--config", "/missing.yaml"); c != 78 {
		t.Fatalf("no config: %d", c)
	}
}

func TestRealClockAndHost(t *testing.T) {
	var c RealClock
	if time.Since(c.Now()) > time.Second {
		t.Fatal("clock")
	}
	tm := c.NewTimer(time.Hour)
	if !tm.Stop() || tm.Reset(time.Millisecond) {
		t.Fatal("timer stop/reset")
	}
	select {
	case <-tm.C():
	case <-time.After(2 * time.Second):
		t.Fatal("timer did not fire")
	}
	e := DefaultEnv()
	if e.Host.EUID() != os.Geteuid() || e.Host.GID() != os.Getgid() || e.Host.PID() != os.Getpid() {
		t.Fatal("host identity")
	}
	if _, err := e.Host.LookupGroup("no-such-group-hopefully"); err == nil {
		t.Fatal("unknown group must fail")
	}
	if g, err := e.Host.LookupGroup(strconv.Itoa(os.Getgid())); err == nil && g < 0 {
		t.Fatal("numeric lookup")
	}
	if !e.Alive(os.Getpid()) || e.Alive(1<<30) {
		t.Fatal("Alive")
	}
	if err := e.Signal(os.Getpid(), syscall.Signal(0)); err != nil {
		t.Fatal(err)
	}
	if exe, err := e.Executable(); err != nil || exe == "" {
		t.Fatal("executable")
	}
	if e.NewClient("") == nil || e.NewClient("/tmp/x.sock") == nil {
		t.Fatal("client")
	}
	if err := e.Exec(context.Background(), []string{"true"}); err != nil {
		t.Fatal(err)
	}
	if err := e.Exec(context.Background(), nil); err == nil {
		t.Fatal("empty argv must fail")
	}
	ch, stop := NotifySignals()
	_ = syscall.Kill(os.Getpid(), syscall.SIGHUP)
	select {
	case s := <-ch:
		if s != syscall.SIGHUP {
			t.Fatalf("got %v", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("signal not delivered")
	}
	stop()
}

func TestDepsAndBackend(t *testing.T) {
	f := newFixture(t, fixOpt{})
	d, err := New(f.cfg, f.env, DefaultRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if d.deps.Logger() == nil || d.deps.Audit() == nil || d.deps.Clock() == nil || d.deps.Okta() == nil {
		t.Fatal("deps accessors")
	}
	if _, err := (&deps{}).Credential(context.Background(), "x"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("no cache yet")
	}
	if _, err := d.deps.Credential(context.Background(), "x"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("unknown provider")
	}
	if _, err := (noOkta{}).Token(context.Background(), domain.OktaTokenRequest{}); !errors.Is(err, domain.ErrConfig) {
		t.Fatal("noOkta")
	}
	p := &domaintest.FakeProvider{ProviderName: "p"}
	if unwrap(guarded{Provider: p}) != domain.Provider(p) || unwrap(p) != domain.Provider(p) {
		t.Fatal("unwrap")
	}
	// backend: refresh and error mapping
	b := backend{c: d.Cache(), clock: f.env.Clock}
	if _, err := b.Credential(context.Background(), "ghost"); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("unknown provider: %v", err)
	}
	if _, err := b.Refresh(context.Background(), "ghost"); err == nil {
		t.Fatal("refresh unknown")
	}
	if err := d.Cache().Register(p, domain.Key{Provider: "p"}, cache.Options{}); err != nil {
		t.Fatal(err)
	}
	if c, err := b.Refresh(context.Background(), "p"); err != nil || c.Value.IsZero() {
		t.Fatalf("refresh: %v", err)
	}
	st := b.Status(context.Background())
	if st.State != domain.StateValid || len(st.Providers) != 1 || st.Providers[0].ExpiresAt == nil {
		t.Fatalf("%+v", st)
	}
}

// FR-R06: a rotated opaque (non-JWT) msgraph refresh token that a foreign
// library embeds in an error must not reach the log output.
func TestRotatedRefreshTokenNeverLogged(t *testing.T) {
	g := newFixture(t, fixOpt{providers: githubProviders("PLACEHOLDER", "pat")})
	g.cfgp = rewriteStorePath(t, g)
	d, err := New(g.cfg, g.env, DefaultRegistry())
	if err != nil {
		t.Fatal(err)
	}
	st, err := d.deps.Store(StoreFileEncrypted)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ver := ""
	var tokens []string
	for i := range 10 { // rotation must not grow the scrubber without bound
		tok := fmt.Sprintf("0.AAAA-opaque-refresh-%02d", i)
		tokens = append(tokens, tok)
		if ver, err = st.Put(ctx, "msgraph-rt", domain.NewSecret(tok), ver); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	log := obs.NewLogger(&buf, slog.LevelDebug, d.scrub)
	last := tokens[len(tokens)-1]
	log.Error("refresh failed", "err", fmt.Errorf("oauth2: cannot fetch token: refresh_token=%s rejected", last))
	if out := buf.String(); strings.Contains(out, last) || !strings.Contains(out, domain.Redacted) {
		t.Fatalf("token leaked or not redacted: %s", out)
	}
	rd, err := st.Get(ctx, "msgraph-rt")
	if err != nil || rd.Value.Reveal() != last {
		t.Fatal(err)
	}
	if got := d.scrub.Scrub(tokens[0]); got != tokens[0] {
		t.Fatalf("oldest rotated value should be evicted (bounded list): %q", got)
	}
	if strings.Contains(d.scrub.Scrub(last), last) {
		t.Fatal("last token must be scrubbed")
	}
}
