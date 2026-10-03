package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/config"
	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/domain/domaintest"
	"github.com/stainedhead/agent-okta-d/internal/ipc"
	"github.com/stainedhead/agent-okta-d/internal/sink"
	"github.com/stainedhead/agent-okta-d/pkg/client"
)

var (
	keyOnce sync.Once
	keyPEM  []byte
)

func testKeyPEM(t testing.TB) []byte {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			panic(err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	})
	return keyPEM
}

// syncBuf is a goroutine-safe buffer that can also log write order.
type syncBuf struct {
	mu  sync.Mutex
	b   bytes.Buffer
	hit func(line string)
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hit != nil {
		for _, l := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
			s.hit(l)
		}
	}
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// world is the fake outside: Okta, ServiceNow, GitHub and Microsoft, all on
// one TLS server; a transport sends every request there whatever its host.
type world struct {
	t   *testing.T
	srv *httptest.Server
	clk *domaintest.FakeClock

	mu         sync.Mutex
	oktaStatus int // 0 = ok
	oktaCode   string
	tokenCalls int
	skew       time.Duration
	snowStatus int
	ghLogin    string
	ghExpiry   string
	graphUPN   string
	otherCode  int
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, clk: domaintest.NewFakeClock(), ghLogin: "agent-gh", graphUPN: "agent@example.com", otherCode: 403}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		skew := w.skew
		w.mu.Unlock()
		rw.Header().Set("Date", w.clk.Now().Add(skew).UTC().Format(http.TimeFormat))
		if r.URL.Path != "/" {
			http.NotFound(rw, r)
			return
		}
		rw.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /oauth2/{id}/v1/token", w.oktaToken)
	mux.HandleFunc("/api/now/table/sys_user", func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		st := w.snowStatus
		w.mu.Unlock()
		if st == 0 {
			st = 200
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			st = 401
		}
		rw.WriteHeader(st)
		_, _ = rw.Write([]byte(`{"result":[]}`))
	})
	mux.HandleFunc("GET /user", func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		login, exp := w.ghLogin, w.ghExpiry
		w.mu.Unlock()
		if exp != "" {
			rw.Header().Set("github-authentication-token-expiration", exp)
		}
		_, _ = fmt.Fprintf(rw, `{"id":4242,"login":%q}`, login)
	})
	mux.HandleFunc("POST /login/device/code", func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write([]byte(`{"device_code":"dc","user_code":"ABCD-1234","verification_uri":"https://github.com/login/device","expires_in":900,"interval":5}`))
	})
	mux.HandleFunc("POST /login/oauth/access_token", func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write([]byte(`{"access_token":"gho_devicetoken0123456789","scope":"repo"}`))
	})
	mux.HandleFunc("POST /{tenant}/oauth2/v2.0/devicecode", func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write([]byte(`{"device_code":"mdc","user_code":"MS-CODE","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":5}`))
	})
	mux.HandleFunc("POST /{tenant}/oauth2/v2.0/token", func(rw http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") == "refresh_token" {
			_, _ = rw.Write([]byte(`{"token_type":"Bearer","access_token":"ms-access-0123456789","refresh_token":"ms-refresh-rotated","expires_in":3600,"scope":"User.Read"}`))
			return
		}
		_, _ = rw.Write([]byte(`{"access_token":"ms-access-0123456789","refresh_token":"ms-refresh-0123456789"}`))
	})
	mux.HandleFunc("GET /v1.0/me", func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		upn := w.graphUPN
		w.mu.Unlock()
		_, _ = fmt.Fprintf(rw, `{"userPrincipalName":%q}`, upn)
	})
	mux.HandleFunc("GET /v1.0/me/", func(rw http.ResponseWriter, r *http.Request) { _, _ = rw.Write([]byte(`{}`)) })
	mux.HandleFunc("GET /v1.0/users/", func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		c := w.otherCode
		w.mu.Unlock()
		rw.WriteHeader(c)
	})
	w.srv = httptest.NewUnstartedServer(mux)
	w.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	w.srv.StartTLS()
	t.Cleanup(w.srv.Close)
	return w
}

func (w *world) oktaToken(rw http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	w.mu.Lock()
	w.tokenCalls++
	n, st, code := w.tokenCalls, w.oktaStatus, w.oktaCode
	w.mu.Unlock()
	if r.Form.Get("client_assertion") == "" || r.Form.Get("grant_type") != "client_credentials" {
		rw.WriteHeader(http.StatusBadRequest)
		_, _ = rw.Write([]byte(`{"error":"invalid_request"}`))
		return
	}
	if st != 0 {
		rw.WriteHeader(st)
		_, _ = fmt.Fprintf(rw, `{"error":%q}`, code)
		return
	}
	_, _ = fmt.Fprintf(rw, `{"token_type":"Bearer","access_token":"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig%d","expires_in":3600,"scope":%q}`, n, r.Form.Get("scope"))
}

func (w *world) calls() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.tokenCalls
}

func (w *world) set(f func(*world)) {
	w.mu.Lock()
	f(w)
	w.mu.Unlock()
}

// redirect sends every request to the fake server.
type redirect struct{ w *world }

func (r redirect) RoundTrip(req *http.Request) (*http.Response, error) {
	u, _ := url.Parse(r.w.srv.URL)
	c := req.Clone(req.Context())
	c.URL.Scheme, c.URL.Host = "https", u.Host
	return r.w.srv.Client().Transport.RoundTrip(c)
}

// autoClock advances the fake clock whenever a timer is created, so polling
// loops (device flows) run instantly.
type autoClock struct{ *domaintest.FakeClock }

func (c autoClock) NewTimer(d time.Duration) domain.Timer {
	t := c.FakeClock.NewTimer(d)
	c.Advance(d)
	return t
}

type fakeHost struct{ euid, gid, pid int }

func (h fakeHost) EUID() int { return h.euid }
func (h fakeHost) GID() int  { return h.gid }
func (h fakeHost) PID() int  { return h.pid }
func (fakeHost) LookupGroup(name string) (int, error) {
	if name == "agents" {
		return os.Getgid(), nil
	}
	return 0, fmt.Errorf("no group %q", name)
}

// execLog records Exec calls.
type execLog struct {
	mu   sync.Mutex
	cmds [][]string
	err  error
}

func (e *execLog) run(_ context.Context, argv []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cmds = append(e.cmds, argv)
	return e.err
}

// fixture is one test installation: config file, key, socket, env.
type fixture struct {
	t      *testing.T
	w      *world
	dir    string // roomy temp dir for files
	sockd  string // short dir for the socket (macOS path limit)
	cfgp   string
	cfg    *config.Config
	env    Env
	stdout *syncBuf
	stderr *syncBuf
	exec   *execLog
	envvar map[string]string
}

type fixOpt struct {
	providers string // extra provider YAML under providers:
	signer    string // override okta.signer block
	allow     string // override ipc.allow_gids list
}

func newFixture(t *testing.T, o fixOpt) *fixture {
	t.Helper()
	w := newWorld(t)
	dir := t.TempDir()
	sockd, err := os.MkdirTemp("", "aod")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockd) })
	keyp := filepath.Join(dir, "okta.pem")
	if err := os.WriteFile(keyp, testKeyPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	signer := o.signer
	if signer == "" {
		signer = fmt.Sprintf("{type: file, key_id: %s, alg: RS256, kid: kid-1}", keyp)
	}
	allow := o.allow
	if allow == "" {
		allow = fmt.Sprint(os.Getgid())
	}
	provs := o.providers
	if provs == "" {
		provs = defaultProviders(dir, w.srv.URL)
	}
	yaml := fmt.Sprintf(`
agent: {id: agent-1}
okta:
  org_url: %s
  client_id: 0oaTEST
  signer: %s
providers:
%s
ipc: {socket: %s, allow_gids: [%s]}
log: {destination: stderr}
`, w.srv.URL, signer, provs, filepath.Join(sockd, "s.sock"), allow)
	cfgp := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgp, []byte(yaml), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgp)
	if err != nil {
		t.Fatalf("fixture config: %v", err)
	}
	f := &fixture{t: t, w: w, dir: dir, sockd: sockd, cfgp: cfgp, cfg: cfg, stdout: &syncBuf{}, stderr: &syncBuf{}, exec: &execLog{}, envvar: map[string]string{}}
	f.env = Env{
		Clock: w.clk, HTTP: &http.Client{Transport: redirect{w}}, Sink: sink.New(),
		PeerCred: ipc.NewPeerCred(), Host: fakeHost{euid: 1001, gid: 99999, pid: os.Getpid()},
		NewClient: func(sock string) DaemonClient {
			if sock == "" {
				sock = cfg.IPC.Socket
			}
			return client.New(client.WithSocketPath(sock))
		},
		Stdin: strings.NewReader(""), Stdout: f.stdout, Stderr: f.stderr,
		Signal: func(int, os.Signal) error { return nil }, Sleep: func(time.Duration) {},
		Alive: func(int) bool { return false }, Exec: f.exec.run,
		DaemonPID:  dialDaemonPID(ipc.NewPeerCred()),
		Executable: func() (string, error) { return "/usr/local/bin/agent-okta-d", nil },
		Getenv:     func(k string) string { return f.envvar[k] },
	}
	return f
}

func defaultProviders(dir, base string) string {
	return fmt.Sprintf(`  aws:
    authorization_server: agents-aws
    scope: aws.assume
    token_file: %s/aws.jwt
    role_arn: arn:aws:iam::222222222222:role/agent-x
    region: us-east-1
  servicenow:
    instance_url: %s
    authorization_server: agents-snow
    scope: snow.agent`, dir, base)
}

func githubProviders(dir, mode string) string {
	return fmt.Sprintf(`  github:
    mode: %s
    login: agent-gh
    store: {type: file-encrypted, secret_id: gh, path: %s/secrets.enc}
    git_identity: {name: Agent One}`, mode, dir)
}

// run starts the daemon and returns it with a stop func and the exit error
// channel.
func (f *fixture) start(t *testing.T) (*Daemon, chan os.Signal, context.CancelFunc, chan error) {
	t.Helper()
	d, err := New(f.cfg, f.env, DefaultRegistry())
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(chan os.Signal, 4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	fin := make(chan struct{})
	go func() { done <- d.Run(ctx, sigs); close(fin) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(PidFile(f.cfg)); err == nil {
			break
		}
		select {
		case err := <-done:
			cancel()
			t.Fatalf("daemon exited during start: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("daemon did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-fin:
		case <-time.After(5 * time.Second):
		}
	})
	return d, sigs, cancel, done
}

func (f *fixture) client() *client.Client { return client.New(client.WithSocketPath(f.cfg.IPC.Socket)) }

func waitErr(t *testing.T, done chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not exit")
		return nil
	}
}

var _ = syscall.SIGUSR1

// recSink records sink removals around a real sink.
type recSink struct {
	Sink
	rec func(op, path string)
}

func (r recSink) Remove(ctx context.Context, spec domain.SinkSpec) error {
	r.rec("remove", spec.Path)
	return r.Sink.Remove(ctx, spec)
}

// rewriteStorePath replaces the PLACEHOLDER dir in the fixture config with the
// real temp dir (the providers block is built before the dir is known to the
// caller) and returns the config path.
func rewriteStorePath(t *testing.T, f *fixture) string {
	t.Helper()
	b, err := os.ReadFile(f.cfgp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.cfgp, []byte(strings.ReplaceAll(string(b), "PLACEHOLDER", f.dir)), 0o640); err != nil {
		t.Fatal(err)
	}
	f.cfg, _ = reload(t, f.cfgp)
	return f.cfgp
}

func reload(t *testing.T, path string) (*config.Config, error) {
	t.Helper()
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return c, nil
}
