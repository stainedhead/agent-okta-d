package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"time"
)

// Environment and defaults.
const (
	// EnvSocket names the environment variable that overrides the default
	// socket path.
	EnvSocket = "AGENT_OKTA_D_SOCKET"
	// DefaultTimeout is the per-request timeout when WithTimeout is not used.
	DefaultTimeout = 5 * time.Second

	maxBody = 1 << 20
)

// DefaultSocketPath returns the platform default socket path. It does not
// consult EnvSocket.
//
// Proposed new assumption A-13 (not yet in docs/assumptions.md): the PRD fixes the directory (/run/agentd on Linux,
// /var/run/agentd on macOS) but not the socket file name; the client assumes
// the file is named agentd.sock directly in it. Deployments that use a
// per-agent subdirectory set EnvSocket or WithSocketPath.
func DefaultSocketPath() string { return defaultSocketFor(runtime.GOOS) }

func defaultSocketFor(goos string) string {
	if goos == "darwin" {
		return "/var/run/agentd/agentd.sock"
	}
	return "/run/agentd/agentd.sock"
}

// Option configures New.
type Option func(*Client)

// WithSocketPath sets the unix socket path, overriding EnvSocket and the
// platform default.
func WithSocketPath(path string) Option { return func(c *Client) { c.socket = path } }

// WithTimeout sets the per-request timeout. Values <= 0 are ignored.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// Client talks to the agent-okta-d daemon over its unix socket. It holds no
// global state and is safe for concurrent use.
type Client struct {
	socket  string
	timeout time.Duration
	http    *http.Client
}

// New builds a Client. The socket path is, in order, WithSocketPath, the
// EnvSocket environment variable, then DefaultSocketPath.
func New(opts ...Option) *Client {
	c := &Client{timeout: DefaultTimeout}
	for _, o := range opts {
		o(c)
	}
	if c.socket == "" {
		c.socket = os.Getenv(EnvSocket)
	}
	if c.socket == "" {
		c.socket = DefaultSocketPath()
	}
	sock := c.socket
	c.http = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
		DisableCompression: true,
		MaxIdleConns:       2,
		IdleConnTimeout:    30 * time.Second,
	}}
	return c
}

// SocketPath returns the socket path in use.
func (c *Client) SocketPath() string { return c.socket }

// Close releases idle connections. The Client stays usable afterwards.
func (c *Client) Close() { c.http.CloseIdleConnections() }

// Credential returns the current credential for provider, refreshing
// synchronously on the daemon side if it is close to expiry.
func (c *Client) Credential(ctx context.Context, provider string) (Credential, error) {
	return c.credential(ctx, http.MethodGet, provider, "")
}

// Refresh forces the daemon to refresh provider's credential and returns it.
func (c *Client) Refresh(ctx context.Context, provider string) (Credential, error) {
	return c.credential(ctx, http.MethodPost, provider, "/refresh")
}

// Status returns the daemon-wide and per-provider state.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var s Status
	err := c.do(ctx, http.MethodGet, endpoint("/v1/status", "/v1/status"), &s)
	return s, err
}

// Identity returns the agent identity the daemon acts for.
func (c *Client) Identity(ctx context.Context) (Identity, error) {
	var i Identity
	err := c.do(ctx, http.MethodGet, endpoint("/v1/identity", "/v1/identity"), &i)
	return i, err
}

func (c *Client) credential(ctx context.Context, method, provider, suffix string) (Credential, error) {
	if provider == "" {
		return Credential{}, fmt.Errorf("%w: provider name required", ErrNotConfigured)
	}
	var cred Credential
	u := endpoint("/v1/credentials/"+provider+suffix, "/v1/credentials/"+url.PathEscape(provider)+suffix)
	if err := c.do(ctx, method, u, &cred); err != nil {
		return Credential{}, err
	}
	if cred.AccessToken.IsZero() {
		return Credential{}, fmt.Errorf("%w: empty access_token", ErrInvalidResponse)
	}
	return cred, nil
}

// endpoint builds a request URL; path is the decoded form, rawPath the
// escaped form (they differ only for provider names needing escaping).
func endpoint(path, rawPath string) *url.URL {
	return &url.URL{Scheme: "http", Host: "agent-okta-d", Path: path, RawPath: rawPath}
}

func (c *Client) do(ctx context.Context, method string, u *url.URL, out any) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req := (&http.Request{Method: method, URL: u, Host: u.Host, Header: http.Header{"Accept": {"application/json"}}}).WithContext(ctx)
	resp, err := c.http.Do(req)
	if err != nil {
		return c.transportErr(ctx, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return c.transportErr(ctx, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return apiError(resp, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidResponse, err)
	}
	return nil
}

func (c *Client) transportErr(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return context.Canceled
	}
	return fmt.Errorf("%w: %w", ErrDaemonUnavailable, err)
}

func apiError(resp *http.Response, body []byte) error {
	ae := &APIError{Status: resp.StatusCode}
	var wire struct {
		Error             string `json:"error"`
		State             State  `json:"state"`
		RetryAfterSeconds int    `json:"retry_after_seconds"`
	}
	if json.Unmarshal(body, &wire) == nil {
		ae.Code, ae.State = wire.Error, wire.State
		if wire.RetryAfterSeconds > 0 {
			ae.RetryAfter = time.Duration(wire.RetryAfterSeconds) * time.Second
		}
	}
	if ae.RetryAfter == 0 {
		if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && n > 0 {
			ae.RetryAfter = time.Duration(n) * time.Second
		}
	}
	return ae
}
