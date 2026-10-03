package clienttest

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Wire error codes the fake can emit.
const (
	// CodeReauthRequired maps to HTTP 401.
	CodeReauthRequired = "reauth_required"
	// CodeRevoked maps to HTTP 403.
	CodeRevoked = "revoked"
	// CodeDegraded maps to HTTP 503 with Retry-After.
	CodeDegraded = "degraded"
	// CodeUnauthorized maps to HTTP 403.
	CodeUnauthorized = "unauthorized"
	// CodeNotConfigured maps to HTTP 404.
	CodeNotConfigured = "not_configured"
	// CodeInternal maps to HTTP 500.
	CodeInternal = "internal"
)

// TB is the subset of testing.TB the fake needs; *testing.T and *testing.B
// satisfy it, and so can a small adapter for runnable examples.
type TB interface {
	Helper()
	Fatalf(format string, args ...any)
	Cleanup(func())
}

// Credential is the body served for a provider.
type Credential struct {
	TokenType   string    `json:"token_type"`
	AccessToken string    `json:"access_token"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Audience    string    `json:"audience"`
}

// ProviderStatus is one entry of Status.
type ProviderStatus struct {
	Provider          string     `json:"provider"`
	State             string     `json:"state"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	LastError         string     `json:"last_error,omitempty"`
	RetryAfterSeconds int        `json:"retry_after_seconds,omitempty"`
}

// Status is the body served for /v1/status.
type Status struct {
	State     string           `json:"state"`
	Providers []ProviderStatus `json:"providers"`
}

// Identity is the body served for /v1/identity.
type Identity struct {
	AgentID       string `json:"agent_id"`
	OktaClientID  string `json:"okta_client_id"`
	KID           string `json:"kid"`
	DaemonVersion string `json:"daemon_version"`
	APIVersion    string `json:"api_version"`
}

// Error describes a daemon error answer. Code is one of the Code constants;
// the HTTP status follows from it unless HTTPStatus overrides it.
type Error struct {
	Code       string
	State      string
	RetryAfter time.Duration
	HTTPStatus int
}

// Request records one request the fake received.
type Request struct {
	Method string
	Path   string
}

// Server is the fake daemon. Create it with New; it is closed automatically
// when the test ends.
type Server struct {
	dir  string
	sock string
	srv  *http.Server
	ln   net.Listener

	mu       sync.Mutex
	creds    map[string]Credential
	refresh  map[string]Credential
	errs     map[string]Error
	global   *Error
	raw      *rawResp
	status   Status
	identity Identity
	delay    time.Duration
	reqs     []Request
}

type rawResp struct {
	status int
	body   string
}

// New starts a fake daemon on a fresh unix socket and registers cleanup with
// t. By default it serves no credentials (every provider answers
// not_configured), an empty valid status and a placeholder identity.
func New(t TB) *Server {
	t.Helper()
	// A short path: unix socket paths are limited to ~104 bytes on macOS.
	dir, err := os.MkdirTemp("", "aod")
	if err != nil {
		t.Fatalf("clienttest: temp dir: %v", err)
	}
	s := &Server{
		dir:      dir,
		sock:     filepath.Join(dir, "s.sock"),
		creds:    map[string]Credential{},
		refresh:  map[string]Credential{},
		errs:     map[string]Error{},
		status:   Status{State: "valid", Providers: []ProviderStatus{}},
		identity: Identity{AgentID: "agent-test", OktaClientID: "0oaTEST", KID: "kid-test", DaemonVersion: "0.0.0-test", APIVersion: "v1"},
	}
	s.ln, err = net.Listen("unix", s.sock)
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("clienttest: listen: %v", err)
	}
	s.srv = &http.Server{Handler: http.HandlerFunc(s.handle), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = s.srv.Serve(s.ln) }()
	t.Cleanup(s.Close)
	return s
}

// DeadSocketPath returns a socket path with nothing listening on it, for
// testing the daemon-unavailable path.
func DeadSocketPath(t TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "aod")
	if err != nil {
		t.Fatalf("clienttest: temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "dead.sock")
}

// SocketPath returns the socket the fake listens on.
func (s *Server) SocketPath() string { return s.sock }

// Close stops the fake and removes its socket. It is safe to call twice.
func (s *Server) Close() {
	_ = s.srv.Close()
	_ = os.RemoveAll(s.dir)
}

// SetCredential serves c for provider.
func (s *Server) SetCredential(provider string, c Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creds[provider] = c
}

// SetRefreshed makes the next refresh of provider serve c, which then becomes
// the current credential.
func (s *Server) SetRefreshed(provider string, c Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh[provider] = c
}

// SetProviderError makes credential and refresh calls for provider fail with
// e. A zero Error clears it.
func (s *Server) SetProviderError(provider string, e Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e == (Error{}) {
		delete(s.errs, provider)
		return
	}
	s.errs[provider] = e
}

// SetGlobalError makes every endpoint fail with e. A zero Error clears it.
func (s *Server) SetGlobalError(e Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e == (Error{}) {
		s.global = nil
		return
	}
	s.global = &e
}

// SetRaw makes every endpoint answer status with body verbatim, for testing
// malformed responses. status 0 clears it.
func (s *Server) SetRaw(status int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if status == 0 {
		s.raw = nil
		return
	}
	s.raw = &rawResp{status: status, body: body}
}

// SetStatus serves st for /v1/status.
func (s *Server) SetStatus(st Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = st
}

// SetIdentity serves id for /v1/identity.
func (s *Server) SetIdentity(id Identity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identity = id
}

// SetDelay makes every answer wait d first, for testing client timeouts.
func (s *Server) SetDelay(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delay = d
}

// Requests returns a copy of the requests received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.reqs...)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.reqs = append(s.reqs, Request{Method: r.Method, Path: r.URL.EscapedPath()})
	delay, global, raw := s.delay, s.global, s.raw
	s.mu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	if raw != nil {
		w.WriteHeader(raw.status)
		_, _ = w.Write([]byte(raw.body))
		return
	}
	if global != nil {
		writeError(w, *global)
		return
	}
	path := r.URL.EscapedPath()
	switch {
	case path == "/healthz" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case path == "/v1/status" && r.Method == http.MethodGet:
		s.mu.Lock()
		st := s.status
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, st)
	case path == "/v1/identity" && r.Method == http.MethodGet:
		s.mu.Lock()
		id := s.identity
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, id)
	case strings.HasPrefix(path, "/v1/credentials/"):
		s.credential(w, r.Method, strings.TrimPrefix(path, "/v1/credentials/"))
	default:
		writeError(w, Error{Code: CodeNotConfigured})
	}
}

func (s *Server) credential(w http.ResponseWriter, method, rest string) {
	refresh := strings.HasSuffix(rest, "/refresh")
	if refresh {
		rest = strings.TrimSuffix(rest, "/refresh")
	}
	if refresh != (method == http.MethodPost) {
		writeError(w, Error{Code: CodeNotConfigured})
		return
	}
	provider, _ := url.PathUnescape(rest) // the server already validated the escaping
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.errs[provider]; ok {
		writeError(w, e)
		return
	}
	if refresh {
		if c, ok := s.refresh[provider]; ok {
			s.creds[provider] = c
			delete(s.refresh, provider)
		}
	}
	c, ok := s.creds[provider]
	if !ok {
		writeError(w, Error{Code: CodeNotConfigured})
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func statusFor(code string) int {
	switch code {
	case CodeReauthRequired:
		return http.StatusUnauthorized
	case CodeRevoked, CodeUnauthorized:
		return http.StatusForbidden
	case CodeNotConfigured:
		return http.StatusNotFound
	case CodeDegraded:
		return http.StatusServiceUnavailable
	}
	return http.StatusInternalServerError
}

func writeError(w http.ResponseWriter, e Error) {
	status := e.HTTPStatus
	if status == 0 {
		status = statusFor(e.Code)
	}
	body := struct {
		Error             string `json:"error"`
		State             string `json:"state,omitempty"`
		RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
	}{Error: e.Code, State: e.State, RetryAfterSeconds: int(e.RetryAfter / time.Second)}
	if e.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(e.RetryAfter/time.Second)))
	}
	writeJSON(w, status, body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
