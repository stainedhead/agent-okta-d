package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// DefaultRetryAfter is the Retry-After hint when the backend gives none.
const DefaultRetryAfter = 30 * time.Second

// Config configures a Server.
type Config struct {
	// AllowGIDs is the default allow-list, used for providers without an entry
	// in ProviderGIDs (config key ipc.allow_gids).
	AllowGIDs []int
	// ProviderGIDs overrides AllowGIDs for a provider. An entry replaces the
	// default; an empty (non-nil) entry denies everyone.
	ProviderGIDs map[string][]int
	// AgentID is stamped on audit events.
	AgentID string
	// Identity is served by GET /v1/identity.
	Identity domain.WireIdentity
	// RetryAfter is the 503 hint when the backend gives none; zero means
	// DefaultRetryAfter.
	RetryAfter time.Duration
}

// Deps are the Server's collaborators.
type Deps struct {
	Backend  Backend
	PeerCred domain.PeerCredReader
	Audit    domain.AuditSink
	Clock    domain.Clock
	Logger   *slog.Logger
}

// Server is the unix-socket HTTP API.
type Server struct {
	cfg  Config
	d    Deps
	http *http.Server
}

type callerKey struct{}

// callerState is the peer-credential result stored per connection.
type callerState struct {
	info domain.CallerInfo
	err  error
}

// New builds a Server. Nil Audit and Logger default to no-ops.
func New(cfg Config, d Deps) *Server {
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}
	if d.Audit == nil {
		d.Audit = discardAudit{}
	}
	if cfg.RetryAfter <= 0 {
		cfg.RetryAfter = DefaultRetryAfter
	}
	s := &Server{cfg: cfg, d: d}
	s.http = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if d.PeerCred == nil {
				return context.WithValue(ctx, callerKey{}, callerState{err: errors.New("no peer credential reader")})
			}
			info, err := d.PeerCred.Read(c)
			return context.WithValue(ctx, callerKey{}, callerState{info: info, err: err})
		},
	}
	return s
}

type discardAudit struct{}

func (discardAudit) Emit(context.Context, domain.AuditEvent) {}

// Serve accepts connections on ln until Shutdown or Close.
func (s *Server) Serve(ln net.Listener) error {
	err := s.http.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown stops accepting and waits for in-flight requests.
func (s *Server) Shutdown(ctx context.Context) error { return s.http.Shutdown(ctx) }

// Close stops the server immediately.
func (s *Server) Close() error { return s.http.Close() }

// allowed reports whether the caller may use provider ("" means any provider,
// for endpoints that are not provider scoped).
func (s *Server) allowed(c domain.CallerInfo, provider string) bool {
	if provider == "" {
		if s.anyMatch(c, s.cfg.AllowGIDs) {
			return true
		}
		for _, g := range s.cfg.ProviderGIDs {
			if s.anyMatch(c, g) {
				return true
			}
		}
		return false
	}
	gids, ok := s.cfg.ProviderGIDs[provider]
	if !ok {
		gids = s.cfg.AllowGIDs
	}
	return s.anyMatch(c, gids)
}

func (s *Server) anyMatch(c domain.CallerInfo, gids []int) bool {
	for _, g := range gids {
		if c.GID == g {
			return true
		}
		for _, sg := range c.Groups {
			if sg == g {
				return true
			}
		}
	}
	return false
}

// ServeHTTP routes requests. Every response is JSON and uncacheable.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	cs, _ := r.Context().Value(callerKey{}).(callerState)
	if cs.err != nil || s.d.PeerCred == nil {
		// Fail closed: no verified peer, no service.
		s.audit(r, domain.AuditServe, "", domain.CallerInfo{}, false, domain.ResultDenied, "policy")
		s.writeErr(w, domain.CodeUnauthorized, "", 0)
		return
	}
	caller := cs.info

	path := r.URL.Path
	switch {
	case path == domain.PathHealthz:
		// DESIGN (new assumption, reported to the orchestrator): liveness needs only a verified peer, not a gid
		// match, so supervisors running as another user can probe it; the body
		// carries no secret.
		s.method(w, r, http.MethodGet, func() { s.write(w, http.StatusOK, domain.WireHealth{Status: "ok"}) })
	case path == domain.PathStatus:
		s.method(w, r, http.MethodGet, func() {
			if !s.allowed(caller, "") {
				s.deny(w, r, "", caller)
				return
			}
			s.write(w, http.StatusOK, s.d.Backend.Status(r.Context()))
		})
	case path == domain.PathIdentity:
		s.method(w, r, http.MethodGet, func() {
			if !s.allowed(caller, "") {
				s.deny(w, r, "", caller)
				return
			}
			s.write(w, http.StatusOK, s.cfg.Identity)
		})
	case strings.HasPrefix(path, domain.PathCredentialPrefix):
		rest := strings.TrimPrefix(path, domain.PathCredentialPrefix)
		if provider, ok := strings.CutSuffix(rest, domain.PathRefreshSuffix); ok && validProvider(provider) {
			s.method(w, r, http.MethodPost, func() { s.credential(w, r, provider, caller, true) })
			return
		}
		if !validProvider(rest) {
			s.writeErr(w, domain.CodeNotConfigured, "", 0)
			return
		}
		s.method(w, r, http.MethodGet, func() { s.credential(w, r, rest, caller, false) })
	default:
		s.writeErr(w, domain.CodeNotConfigured, "", 0)
	}
}

// validProvider rejects empty names and anything with a path separator.
func validProvider(p string) bool { return p != "" && !strings.Contains(p, "/") }

func (s *Server) method(w http.ResponseWriter, r *http.Request, want string, f func()) {
	if r.Method != want {
		w.Header().Set("Allow", want)
		s.write(w, http.StatusMethodNotAllowed, domain.WireError{Error: CodeMethodNotAllowed})
		return
	}
	f()
}

// CodeMethodNotAllowed is the wire error code of a 405 response. It is not in
// the frozen domain code list; see the WS-E report.
const CodeMethodNotAllowed = "method_not_allowed"

func (s *Server) credential(w http.ResponseWriter, r *http.Request, provider string, caller domain.CallerInfo, force bool) {
	ev := domain.AuditServe
	if force {
		ev = domain.AuditRefresh
	}
	if !s.allowed(caller, provider) {
		s.deny(w, r, provider, caller)
		return
	}
	ctx := r.Context()
	// Fail closed on revocation even if the backend would still hold a value.
	if st := s.d.Backend.Status(ctx); st.State == domain.StateRevoked {
		s.audit(r, ev, provider, caller, true, domain.ResultError, "revoked")
		s.writeErr(w, domain.CodeRevoked, domain.StateRevoked, 0)
		return
	}
	var (
		cred domain.Credential
		err  error
	)
	if force {
		cred, err = s.d.Backend.Refresh(ctx, provider)
	} else {
		cred, err = s.d.Backend.Credential(ctx, provider)
	}
	if err != nil {
		s.audit(r, ev, provider, caller, true, domain.ResultError, errClass(err))
		s.writeBackendErr(w, err)
		return
	}
	if verr := cred.Validate(); verr != nil {
		// Never serve a malformed credential.
		s.audit(r, ev, provider, caller, true, domain.ResultError, domain.ErrorClass(verr))
		s.writeErr(w, domain.CodeInternal, "", 0)
		return
	}
	e := domain.AuditEvent{TS: s.now(), AgentID: s.cfg.AgentID, Event: ev, Provider: provider, Result: domain.ResultOK}.
		WithCaller(caller).WithCredential(cred)
	s.d.Audit.Emit(ctx, e)
	s.write(w, http.StatusOK, domain.NewWireCredential(cred))
}

func errClass(err error) string {
	if errors.Is(err, ErrNotConfigured) {
		return "not_configured"
	}
	return domain.ErrorClass(err)
}

func (s *Server) writeBackendErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrRevoked):
		s.writeErr(w, domain.CodeRevoked, domain.StateRevoked, 0)
	case errors.Is(err, domain.ErrReauthRequired):
		s.writeErr(w, domain.CodeReauthRequired, domain.StateReauthRequired, 0)
	case errors.Is(err, ErrNotConfigured):
		s.writeErr(w, domain.CodeNotConfigured, "", 0)
	case errors.Is(err, domain.ErrTransient):
		d, ok := domain.RetryAfter(err)
		if !ok {
			d = s.cfg.RetryAfter
		}
		s.writeErr(w, domain.CodeDegraded, domain.StateDegraded, d)
	default:
		s.writeErr(w, domain.CodeInternal, "", 0)
	}
}

func (s *Server) deny(w http.ResponseWriter, r *http.Request, provider string, caller domain.CallerInfo) {
	s.audit(r, domain.AuditServe, provider, caller, true, domain.ResultDenied, "policy")
	s.writeErr(w, domain.CodeUnauthorized, "", 0)
}

func (s *Server) now() time.Time {
	if s.d.Clock == nil {
		return time.Now().UTC()
	}
	return s.d.Clock.Now().UTC()
}

func (s *Server) audit(r *http.Request, ev domain.AuditEventType, provider string, caller domain.CallerInfo, haveCaller bool, result, class string) {
	e := domain.AuditEvent{TS: s.now(), AgentID: s.cfg.AgentID, Event: ev, Provider: provider, Result: result, ErrorClass: class}
	if haveCaller {
		e = e.WithCaller(caller)
	}
	s.d.Audit.Emit(r.Context(), e)
}

// writeErr writes a WireError with the status of code. A positive retryAfter
// sets both the Retry-After header and the body field, rounded up to whole
// seconds (at least 1).
func (s *Server) writeErr(w http.ResponseWriter, code string, state domain.State, retryAfter time.Duration) {
	body := domain.WireError{Error: code, State: state}
	if retryAfter > 0 {
		secs := max(int(math.Ceil(retryAfter.Seconds())), 1)
		body.RetryAfterSeconds = secs
		w.Header().Set("Retry-After", strconv.Itoa(secs))
	}
	s.write(w, domain.HTTPStatus(code), body)
}

func (s *Server) write(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.d.Logger.Warn("ipc: write response", "err", err)
	}
}
