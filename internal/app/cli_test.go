package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/pkg/client"
)

type stubClient struct {
	cred      client.Credential
	err       error
	st        client.Status
	stErr     error
	id        client.Identity
	idErr     error
	refreshed []string
}

func (s *stubClient) Credential(context.Context, string) (client.Credential, error) {
	return s.cred, s.err
}

func (s *stubClient) Refresh(_ context.Context, p string) (client.Credential, error) {
	s.refreshed = append(s.refreshed, p)
	return s.cred, s.err
}
func (s *stubClient) Status(context.Context) (client.Status, error)     { return s.st, s.stErr }
func (s *stubClient) Identity(context.Context) (client.Identity, error) { return s.id, s.idErr }

func stub(token string) *stubClient {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	return &stubClient{cred: client.Credential{TokenType: "Bearer", AccessToken: client.NewSecret(token), IssuedAt: now, ExpiresAt: now.Add(time.Hour), Audience: "aud"},
		id: client.Identity{AgentID: "agent-1", OktaClientID: "0oa", KID: "k", DaemonVersion: "v"}}
}

func (f *fixture) use(s DaemonClient) { f.env.NewClient = func(string) DaemonClient { return s } }

func (f *fixture) main(args ...string) int {
	f.stdout.mu.Lock()
	f.stdout.b.Reset()
	f.stdout.mu.Unlock()
	return Main(append(args, "--config", f.cfgp), f.env, nil)
}

func (f *fixture) mainNoCfg(args ...string) int { return Main(args, f.env, nil) }

func TestMainBasics(t *testing.T) {
	f := newFixture(t, fixOpt{})
	if c := f.mainNoCfg(); c != ExitUsage {
		t.Fatalf("no args: %d", c)
	}
	if c := f.mainNoCfg("bogus"); c != ExitUsage {
		t.Fatalf("unknown: %d", c)
	}
	if c := f.mainNoCfg("help"); c != 0 || !strings.Contains(f.stdout.String(), "usage:") {
		t.Fatalf("help: %d", c)
	}
	if c := f.mainNoCfg("version"); c != 0 || !strings.Contains(f.stdout.String(), "agent-okta-d 0.0.0-dev") {
		t.Fatalf("version: %d %q", c, f.stdout.String())
	}
	if c := f.mainNoCfg("status", "--nope"); c != ExitUsage {
		t.Fatalf("bad flag: %d", c)
	}
	if c := f.mainNoCfg("status", "-h"); c != 0 {
		t.Fatalf("-h: %d", c)
	}
	if c := f.mainNoCfg("status", "extra"); c != ExitUsage {
		t.Fatalf("extra arg: %d", c)
	}
	if c := f.mainNoCfg("run", "--config", "/definitely/missing.yaml"); c != domain.ExitConfig {
		t.Fatalf("missing config should exit 78, got %d", c)
	}
}

func TestConfigPathResolution(t *testing.T) {
	f := newFixture(t, fixOpt{})
	fl := newFlags("x", f.env)
	if got := fl.path(f.env); got != DefaultConfigPath {
		t.Fatalf("default %q", got)
	}
	f.envvar[EnvConfig] = "/from/env.yaml"
	if got := fl.path(f.env); got != "/from/env.yaml" {
		t.Fatalf("env %q", got)
	}
	fl.config = "/flag.yaml"
	if got := fl.path(f.env); got != "/flag.yaml" {
		t.Fatalf("flag %q", got)
	}
}

func TestTokenCommand(t *testing.T) {
	f := newFixture(t, fixOpt{})
	f.use(stub("tok-0123456789"))
	if c := f.mainNoCfg("token", "aws"); c != 0 || f.stdout.String() != "tok-0123456789\n" {
		t.Fatalf("raw: %d %q", c, f.stdout.String())
	}
	if c := f.mainNoCfg("token", "aws", "--format", "json"); c != 0 || !strings.Contains(f.stdout.String(), `"access_token":"tok-0123456789"`) {
		t.Fatalf("json: %d %q", c, f.stdout.String())
	}
	s := stub("tok-0123456789")
	f.use(s)
	if c := f.mainNoCfg("token", "aws", "--refresh"); c != 0 || len(s.refreshed) != 1 {
		t.Fatalf("refresh: %d %v", c, s.refreshed)
	}
	if c := f.mainNoCfg("token", "aws", "--format", "xml"); c != ExitUsage {
		t.Fatalf("bad format: %d", c)
	}
	if c := f.mainNoCfg("token"); c != ExitUsage {
		t.Fatalf("missing provider: %d", c)
	}
	for name, tc := range map[string]struct {
		err  error
		code int
		msg  string
	}{
		"revoked":     {&client.APIError{Status: 403, Code: "revoked"}, 77, ""},
		"reauth":      {&client.APIError{Status: 401, Code: "reauth_required"}, 1, "enroll aws"},
		"degraded":    {&client.APIError{Status: 503, Code: "degraded", RetryAfter: 30 * time.Second}, 1, "retry in 30s"},
		"degraded2":   {&client.APIError{Status: 503, Code: "degraded"}, 1, "is degraded"},
		"unreachable": {client.ErrDaemonUnavailable, 3, "unreachable"},
	} {
		t.Run(name, func(t *testing.T) {
			f.stderr.mu.Lock()
			f.stderr.b.Reset()
			f.stderr.mu.Unlock()
			f.use(&stubClient{err: tc.err})
			if c := f.mainNoCfg("token", "aws"); c != tc.code || !strings.Contains(f.stderr.String(), tc.msg) {
				t.Fatalf("code %d stderr %q", c, f.stderr.String())
			}
		})
	}
}

func TestStatusCommand(t *testing.T) {
	f := newFixture(t, fixOpt{})
	exp := time.Date(2026, 10, 3, 13, 0, 0, 0, time.UTC)
	s := stub("x")
	s.st = client.Status{State: client.StateValid, Providers: []client.ProviderStatus{{Provider: "aws", State: client.StateValid, ExpiresAt: &exp}}}
	f.use(s)
	if c := f.mainNoCfg("status"); c != 0 || !strings.Contains(f.stdout.String(), "daemon: valid") || !strings.Contains(f.stdout.String(), "agent-1") {
		t.Fatalf("valid: %d %q", c, f.stdout.String())
	}
	if c := f.mainNoCfg("status", "--json"); c != 0 || !strings.Contains(f.stdout.String(), `"state":"valid"`) {
		t.Fatalf("json: %d %q", c, f.stdout.String())
	}
	s.idErr = errors.New("no identity")
	if c := f.mainNoCfg("status"); c != 0 {
		t.Fatalf("identity error must not fail status: %d", c)
	}
	s.st = client.Status{State: client.StateValid, Providers: []client.ProviderStatus{{Provider: "github", State: client.StateReauthRequired, LastError: "reauth_required"}}}
	if c := f.mainNoCfg("status"); c != 1 || !strings.Contains(f.stdout.String(), "enroll github") {
		t.Fatalf("reauth: %d %q", c, f.stdout.String())
	}
	s.st = client.Status{State: client.StateDegraded, Providers: []client.ProviderStatus{{Provider: "aws", State: client.StateDegraded, RetryAfterSeconds: 12}}}
	if c := f.mainNoCfg("status"); c != 1 || !strings.Contains(f.stdout.String(), "retry_after=12s") {
		t.Fatalf("degraded: %d %q", c, f.stdout.String())
	}
	s.st = client.Status{State: client.StateRevoked}
	if c := f.mainNoCfg("status"); c != 77 {
		t.Fatalf("revoked: %d", c)
	}
	s.st = client.Status{State: client.StateValid, Providers: []client.ProviderStatus{{Provider: "aws", State: client.StateDegraded}}}
	if c := f.mainNoCfg("status"); c != 1 {
		t.Fatalf("provider degraded: %d", c)
	}
	s.stErr = client.ErrDaemonUnavailable
	if c := f.mainNoCfg("status"); c != 3 {
		t.Fatalf("unreachable: %d", c)
	}
}

func TestEnvCommand(t *testing.T) {
	f := newFixture(t, fixOpt{providers: defaultProviders("/x", "https://x.example") + "\n" + githubProviders("/x", "pat")})
	if c := f.main("env", "aws"); c != 0 || !strings.Contains(f.stdout.String(), "export AWS_WEB_IDENTITY_TOKEN_FILE=") {
		t.Fatalf("aws: %d %q", c, f.stdout.String())
	}
	f.use(stub("ghp_stub0123456789"))
	if c := f.main("env", "github"); c != 0 || f.stdout.String() != "export GH_TOKEN='ghp_stub0123456789'\n" {
		t.Fatalf("github: %d %q", c, f.stdout.String())
	}
	if c := f.main("env", "servicenow"); c != ExitUsage {
		t.Fatalf("other: %d", c)
	}
	f.use(&stubClient{err: &client.APIError{Status: 401, Code: "reauth_required"}})
	if c := f.main("env", "github"); c != 1 {
		t.Fatalf("reauth: %d", c)
	}
	if c := f.mainNoCfg("env", "aws", "--config", "/missing.yaml"); c != 78 {
		t.Fatalf("no config: %d", c)
	}
	// aws not configured at all
	g := newFixture(t, fixOpt{providers: githubProviders("/x", "pat")})
	if c := g.main("env", "aws"); c != 78 {
		t.Fatalf("aws absent: %d", c)
	}
}

func TestCredentialHelper(t *testing.T) {
	f := newFixture(t, fixOpt{providers: githubProviders("/x", "pat")})
	f.use(stub("ghp_stub0123456789"))
	f.env.Stdin = strings.NewReader("protocol=https\nhost=github.com\n\n")
	if c := f.main("credential-helper", "github", "get"); c != 0 || f.stdout.String() != "username=agent-gh\npassword=ghp_stub0123456789\n" {
		t.Fatalf("get: %d %q", c, f.stdout.String())
	}
	f.env.Stdin = strings.NewReader("protocol=https\nhost=gitlab.com\n\n")
	if c := f.main("credential-helper", "github", "get"); c != 0 || f.stdout.String() != "" {
		t.Fatalf("other origin: %d %q", c, f.stdout.String())
	}
	f.env.Stdin = strings.NewReader("x=y\n")
	if c := f.main("credential-helper", "github", "store"); c != 0 {
		t.Fatalf("store: %d", c)
	}
	f.env.Stdin = strings.NewReader("protocol=https\nhost=github.com\n\n")
	if c := f.mainNoCfg("credential-helper", "github", "get", "--login", "me", "--web-base", "https://github.com"); c != 0 || !strings.Contains(f.stdout.String(), "username=me") {
		t.Fatalf("flags: %d %q", c, f.stdout.String())
	}
	if c := f.main("credential-helper", "aws", "get"); c != ExitUsage {
		t.Fatalf("non-github: %d", c)
	}
	if c := f.main("credential-helper", "github"); c != ExitUsage {
		t.Fatalf("missing op: %d", c)
	}
	f.use(&stubClient{err: client.ErrDegraded})
	f.env.Stdin = strings.NewReader("protocol=https\nhost=github.com\n\n")
	if c := f.main("credential-helper", "github", "get"); c != 1 {
		t.Fatalf("degraded: %d", c)
	}
	if c := f.mainNoCfg("credential-helper", "github", "get", "--config", "/missing.yaml"); c != 78 {
		t.Fatalf("no config: %d", c)
	}
}

func TestConfigureAWS(t *testing.T) {
	f := newFixture(t, fixOpt{})
	if c := f.main("configure", "aws"); c != 0 || !strings.Contains(f.stdout.String(), "[profile agent]") ||
		!strings.Contains(f.stdout.String(), "role_session_name = agent-1") {
		t.Fatalf("profile: %d %q", c, f.stdout.String())
	}
	if c := f.main("configure", "aws", "--env"); c != 0 || !strings.Contains(f.stdout.String(), "export AWS_ROLE_ARN=") {
		t.Fatalf("env: %d", c)
	}
	target := filepath.Join(f.dir, "aws-config")
	if err := os.WriteFile(target, []byte("[default]\nregion = x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := f.main("configure", "aws", "--write", target); c != 0 {
		t.Fatalf("write: %d", c)
	}
	b, _ := os.ReadFile(target)
	if !strings.Contains(string(b), "[default]\nregion = x\n[profile agent]") {
		t.Fatalf("file: %q", b)
	}
	if c := f.main("configure", "aws", "--write", target); c != 1 {
		t.Fatalf("duplicate must fail: %d", c)
	}
	if c := f.main("configure", "aws", "--write", filepath.Join(f.dir, "no", "such", "dir", "c")); c != 1 {
		t.Fatalf("unwritable: %d", c)
	}
	g := newFixture(t, fixOpt{providers: githubProviders("/x", "pat")})
	if c := g.main("configure", "aws"); c != 78 {
		t.Fatalf("no aws: %d", c)
	}
	if c := f.mainNoCfg("configure"); c != ExitUsage {
		t.Fatalf("no sub: %d", c)
	}
	if c := f.mainNoCfg("configure", "zzz"); c != ExitUsage {
		t.Fatalf("bad sub: %d", c)
	}
}

func TestConfigureGit(t *testing.T) {
	f := newFixture(t, fixOpt{providers: githubProviders("/x", "pat")})
	f.use(stub("ghp_stub0123456789"))
	if c := f.main("configure", "git"); c != 0 {
		t.Fatalf("print: %d %s", c, f.stderr.String())
	}
	out := f.stdout.String()
	for _, want := range []string{`[credential "https://github.com"]`, "credential-helper github", "name = Agent One", "email = 4242+agent-gh@users.noreply.github.com"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
	if c := f.main("configure", "git", "--no-identity"); c != 0 || strings.Contains(f.stdout.String(), "[user]") {
		t.Fatalf("no-identity: %d %q", c, f.stdout.String())
	}
	if c := f.main("configure", "git", "--apply"); c != 0 || len(f.exec.cmds) != 4 {
		t.Fatalf("apply: %d %v", c, f.exec.cmds)
	}
	f.exec.err = errors.New("git missing")
	if c := f.main("configure", "git", "--apply"); c != 1 {
		t.Fatalf("exec failure: %d", c)
	}
	f.use(&stubClient{err: client.ErrDegraded})
	if c := f.main("configure", "git"); c != 1 {
		t.Fatalf("daemon down: %d", c)
	}
	f.w.set(func(w *world) { w.ghLogin = "someone-else" })
	f.use(stub("ghp_stub0123456789"))
	if c := f.main("configure", "git"); c != 1 {
		t.Fatalf("wrong user: %d", c)
	}
	g := newFixture(t, fixOpt{})
	if c := g.main("configure", "git"); c != 78 {
		t.Fatalf("no github: %d", c)
	}
	f.env.Executable = func() (string, error) { return "", errors.New("no exe") }
	if c := f.main("configure", "git"); c != 1 {
		t.Fatalf("no executable: %d", c)
	}
}

func TestConfigureGH(t *testing.T) {
	f := newFixture(t, fixOpt{})
	if c := f.mainNoCfg("configure", "gh"); c != ExitUsage {
		t.Fatalf("missing gh path: %d", c)
	}
	if c := f.mainNoCfg("configure", "gh", "--gh-path", "/usr/bin/gh"); c != 0 || !strings.Contains(f.stdout.String(), "token github --format raw") {
		t.Fatalf("print: %d %q", c, f.stdout.String())
	}
	out := filepath.Join(f.dir, "gh")
	if c := f.mainNoCfg("configure", "gh", "--gh-path", "/usr/bin/gh", "--output", out); c != 0 {
		t.Fatalf("output: %d", c)
	}
	if fi, err := os.Stat(out); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("shim mode: %v %v", fi, err)
	}
	if c := f.mainNoCfg("configure", "gh", "--gh-path", "/usr/bin/gh", "--output", filepath.Join(f.dir, "no", "dir", "gh")); c != 1 {
		t.Fatalf("unwritable: %d", c)
	}
	if c := f.mainNoCfg("configure", "gh", "--gh-path", "gh\nx"); c != 78 {
		t.Fatalf("bad path: %d", c)
	}
	f.env.Executable = func() (string, error) { return "", errors.New("no exe") }
	if c := f.mainNoCfg("configure", "gh", "--gh-path", "/usr/bin/gh"); c != 1 {
		t.Fatalf("no exe: %d", c)
	}
}

func TestEnrollGitHubPATThenServe(t *testing.T) {
	f := newFixture(t, fixOpt{providers: githubProviders("PLACEHOLDER", "pat")})
	f.w.set(func(w *world) { w.ghExpiry = "2027-09-01 00:00:00 UTC" })
	f.env.Stdin = strings.NewReader("ghp_enrolled_token_0123456789\n")
	s := stub("x")
	s.err = errors.New("daemon not running")
	f.use(s)
	cfgp := rewriteStorePath(t, f)
	if c := Main([]string{"enroll", "github", "--mode", "pat", "--config", cfgp}, f.env, nil); c != 0 {
		t.Fatalf("enroll: %d %s", c, f.stderr.String())
	}
	if !strings.Contains(f.stdout.String(), "enrolled github user agent-gh") || !strings.Contains(f.stdout.String(), "was not told to refresh") {
		t.Fatalf("output: %q", f.stdout.String())
	}
	// A daemon started afterwards serves the enrolled token; the agent can read it.
	f.cfg, _ = reload(t, cfgp)
	_, _, _, _ = f.start(t)
	cred, err := f.client().Credential(context.Background(), "github")
	if err != nil || cred.AccessToken.Reveal() != "ghp_enrolled_token_0123456789" {
		t.Fatalf("served %v %v", cred, err)
	}
}

func TestEnrollGitHubErrors(t *testing.T) {
	f := newFixture(t, fixOpt{providers: githubProviders("PLACEHOLDER", "pat")})
	cfgp := rewriteStorePath(t, f)
	run := func(stdin string, args ...string) int {
		f.env.Stdin = strings.NewReader(stdin)
		return Main(append([]string{"enroll", "github", "--config", cfgp}, args...), f.env, nil)
	}
	if c := run("ghp_x\n", "--mode", "oauth_device"); c != 78 {
		t.Fatalf("mode mismatch: %d", c)
	}
	if c := run("ghp_x\n", "--expires", "tomorrow"); c != ExitUsage {
		t.Fatalf("bad expires: %d", c)
	}
	if c := run(""); c != 78 {
		t.Fatalf("empty stdin: %d", c)
	}
	f.w.set(func(w *world) { w.ghLogin = "other" })
	if c := run("ghp_x0123456789\n", "--expires", "2027-01-01"); c != 1 {
		t.Fatalf("wrong login: %d", c)
	}
	g := newFixture(t, fixOpt{})
	if c := g.main("enroll", "github"); c != 78 {
		t.Fatalf("no github: %d", c)
	}
	if c := f.mainNoCfg("enroll"); c != ExitUsage {
		t.Fatalf("no sub: %d", c)
	}
	if c := f.mainNoCfg("enroll", "zzz"); c != ExitUsage {
		t.Fatalf("bad sub: %d", c)
	}
}

func TestEnrollGitHubDevice(t *testing.T) {
	f := newFixture(t, fixOpt{providers: githubProviders("PLACEHOLDER", "oauth_device")})
	cfgp := rewriteStorePath(t, f)
	f.env.Clock = autoClock{f.w.clk}
	f.use(&stubClient{err: errors.New("down")})
	if c := Main([]string{"enroll", "github", "--config", cfgp}, f.env, nil); c != 0 {
		t.Fatalf("device enroll: %d %s", c, f.stderr.String())
	}
	if !strings.Contains(f.stdout.String(), "ABCD-1234") {
		t.Fatalf("no user code shown: %q", f.stdout.String())
	}
}

func TestEnrollMSGraphAndOkta(t *testing.T) {
	prov := `  msgraph:
    tenant_id: tenant-1
    app_client_id: app-1
    upn: agent@example.com
    scopes: [User.Read, offline_access]
    probe_other_user: boss@example.com
    store: {type: file-encrypted, secret_id: mg, path: PLACEHOLDER/m.enc}`
	f := newFixture(t, fixOpt{providers: prov})
	cfgp := rewriteStorePath(t, f)
	f.env.Clock = autoClock{f.w.clk}
	s := stub("x")
	f.use(s)
	if c := Main([]string{"enroll", "msgraph", "--config", cfgp}, f.env, nil); c != 0 {
		t.Fatalf("msgraph enroll: %d %s", c, f.stderr.String())
	}
	if !strings.Contains(f.stdout.String(), "MS-CODE") || len(s.refreshed) != 1 {
		t.Fatalf("output %q refreshed %v", f.stdout.String(), s.refreshed)
	}
	f.w.set(func(w *world) { w.graphUPN = "someone-else@example.com" })
	if c := Main([]string{"enroll", "msgraph", "--config", cfgp}, f.env, nil); c != 1 {
		t.Fatalf("wrong user must fail: %d", c)
	}
	g := newFixture(t, fixOpt{})
	if c := g.main("enroll", "msgraph"); c != 78 {
		t.Fatalf("no msgraph: %d", c)
	}
	if c := f.main("enroll", "okta"); c != 0 || !strings.Contains(f.stdout.String(), `"kty":"RSA"`) || !strings.Contains(f.stdout.String(), "checklist") {
		t.Fatalf("okta: %d %q", c, f.stdout.String())
	}
}

func TestEnrollStoreUnavailable(t *testing.T) {
	prov := `  github:
    mode: pat
    login: agent-gh
    store: {type: aws-secretsmanager, secret_id: gh}`
	f := newFixture(t, fixOpt{providers: prov})
	f.env.Stdin = strings.NewReader("ghp_x0123456789\n")
	if c := f.main("enroll", "github"); c != 78 || !strings.Contains(f.stderr.String(), "not available in this build") {
		t.Fatalf("%d %s", c, f.stderr.String())
	}
	m := newFixture(t, fixOpt{providers: `  msgraph:
    tenant_id: t
    app_client_id: a
    upn: u@example.com
    scopes: [offline_access]
    store: {type: keychain, secret_id: m}`})
	if c := m.main("enroll", "msgraph"); c != 78 {
		t.Fatalf("keychain stub: %d", c)
	}
}

func TestRunDoctorAndRevokeCommands(t *testing.T) {
	f := newFixture(t, fixOpt{})
	f.env.STS = fakeSTS{arn: goodARN}
	if c := f.main("doctor"); c != 0 || !strings.Contains(f.stdout.String(), "[ok  ] provider:aws:probe") {
		t.Fatalf("doctor: %d\n%s", c, f.stdout.String())
	}
	f.env.STS = nil
	if c := f.main("doctor"); c != 1 {
		t.Fatalf("doctor without STS: %d", c)
	}
	g := newFixture(t, fixOpt{signer: "{type: kms, key_id: x, alg: RS256, kid: k}"})
	if c := g.main("doctor"); c != 78 {
		t.Fatalf("doctor config: %d", c)
	}

	// run through the CLI, stopped by SIGTERM.
	sigs := make(chan os.Signal, 1)
	done := make(chan int, 1)
	go func() { done <- Main([]string{"run", "--config", f.cfgp}, f.env, sigs) }()
	for range 400 {
		if _, err := os.Stat(PidFile(f.cfg)); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := f.client().Credential(context.Background(), "aws"); err != nil {
		t.Fatal(err)
	}
	sigs <- syscall.SIGTERM
	if c := <-done; c != 0 {
		t.Fatalf("run exit %d: %s", c, f.stderr.String())
	}
	// run with a bad provider config exits 78.
	g2 := newFixture(t, fixOpt{signer: "{type: tpm, alg: RS256, kid: k}"})
	if c := g2.main("run"); c != 78 {
		t.Fatalf("run config: %d", c)
	}
}
