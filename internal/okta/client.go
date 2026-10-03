package okta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

const (
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	maxResponseBytes    = 1 << 20
	// MaxClockSkew is the self-test limit (FR-9: skew < 30 s).
	MaxClockSkew = 30 * time.Second
	// maxRetryHint caps a server supplied retry delay so a bogus reset header
	// cannot park the refresher for hours.
	maxRetryHint = 10 * time.Minute
	minRetryHint = time.Second
)

// AuthServer describes one Okta custom authorization server (PRD 6.1).
type AuthServer struct {
	// ID is the authorization server id in the token URL
	// {org}/oauth2/{ID}/v1/token, for example "aus1abc..." or "default".
	ID string
	// Audience is the configured audience of the server (for example
	// "sts.amazonaws.com"). Okta does not echo it, so it is reported as
	// configured on OktaToken.Audience.
	Audience string
}

// Config configures a Client.
type Config struct {
	// OrgURL is the Okta org, for example https://EXAMPLE.okta.com. Plain
	// http is accepted only for loopback hosts (tests).
	OrgURL   string
	ClientID string
	// AuthServers maps the config name used in OktaTokenRequest.AuthServer.
	AuthServers map[string]AuthServer
	Signer      domain.Signer
	// Alg is RS256 (default) or ES256 (ASSUMPTION(A-01)).
	Alg        string
	Clock      domain.Clock
	HTTPClient *http.Client // defaults to a client with a 15 s timeout
	// AssertionTTL defaults to 60 s.
	AssertionTTL time.Duration
}

// Client implements domain.OktaTokenSource with private_key_jwt.
type Client struct {
	org     string
	servers map[string]AuthServer
	builder *AssertionBuilder
	clock   domain.Clock
	hc      *http.Client
}

var _ domain.OktaTokenSource = (*Client)(nil)

// NewClient validates c and returns a Client. Problems are domain.ErrConfig.
func NewClient(c Config) (*Client, error) {
	u, err := url.Parse(c.OrgURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, domain.NewConfigError("okta.org_url", "must be an absolute URL without credentials, query or fragment")
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !isLoopback(u.Hostname())) {
		return nil, domain.NewConfigError("okta.org_url", "must use https")
	}
	if len(c.AuthServers) == 0 {
		return nil, domain.NewConfigError("okta.authorization_servers", "at least one authorization server is required")
	}
	for name, as := range c.AuthServers {
		if name == "" || as.ID == "" || strings.ContainsAny(as.ID, "/?#") {
			return nil, domain.NewConfigError("okta.authorization_servers."+name, "needs a name and an id without path characters")
		}
	}
	b := &AssertionBuilder{ClientID: c.ClientID, Signer: c.Signer, Alg: c.Alg, Clock: c.Clock, TTL: c.AssertionTTL}
	if _, _, err := b.validate(); err != nil {
		return nil, err
	}
	hc := http.DefaultClient
	if c.HTTPClient != nil {
		hc = c.HTTPClient
	}
	cp := *hc
	if cp.Timeout == 0 {
		cp.Timeout = 15 * time.Second
	}
	// Never follow redirects: the request body carries a client assertion.
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	servers := make(map[string]AuthServer, len(c.AuthServers))
	for k, v := range c.AuthServers {
		servers[k] = v
	}
	return &Client{
		org:     strings.TrimRight(u.String(), "/"),
		servers: servers,
		builder: b,
		clock:   c.Clock,
		hc:      &cp,
	}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// TokenURL returns the token endpoint of the named authorization server; it is
// also the assertion audience.
func (c *Client) TokenURL(authServer string) (string, error) {
	as, ok := c.servers[authServer]
	if !ok {
		return "", domain.NewConfigError("okta.authorization_servers."+authServer, "unknown authorization server")
	}
	return c.org + "/oauth2/" + url.PathEscape(as.ID) + "/v1/token", nil
}

type tokenResponse struct {
	AccessToken string      `json:"access_token"`
	TokenType   string      `json:"token_type"`
	ExpiresIn   json.Number `json:"expires_in"`
	Scope       string      `json:"scope"`
	Error       string      `json:"error"`
}

// Token implements domain.OktaTokenSource (client_credentials with a signed
// client assertion). Failures map onto the domain taxonomy:
//   - network error, timeout, 429, 5xx: ErrTransient (RetryAfter set from the
//     X-Rate-Limit-Reset or Retry-After header on 429)
//   - invalid_client, unauthorized_client: ErrAuthDefinitive (the cache confirms twice before revoking, FR-6)
//   - any other rejection or malformed response: ErrProvider
func (c *Client) Token(ctx context.Context, req domain.OktaTokenRequest) (domain.OktaToken, error) {
	tokenURL, err := c.TokenURL(req.AuthServer)
	if err != nil {
		return domain.OktaToken{}, err
	}
	if req.Scope == "" || strings.ContainsAny(req.Scope, "\r\n") {
		return domain.OktaToken{}, domain.NewConfigError("scope", "a custom scope is required")
	}
	as := c.servers[req.AuthServer]
	a, err := c.builder.Build(ctx, tokenURL)
	if err != nil {
		return domain.OktaToken{}, err
	}
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"scope":                 {req.Scope},
		"client_assertion_type": {clientAssertionType},
		"client_assertion":      {a.JWT.Reveal()},
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return domain.OktaToken{}, domain.Wrap(domain.ErrConfig, errors.New("cannot build token request"))
	}
	hreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hreq.Header.Set("Accept", "application/json")

	issuedAt := c.clock.Now()
	resp, err := c.hc.Do(hreq)
	if err != nil {
		return domain.OktaToken{}, transportErr(ctx, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return domain.OktaToken{}, domain.NewTransient(errors.New("reading token response failed"), 0)
	}

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return domain.OktaToken{}, domain.NewTransient(errors.New("okta rate limited (429)"), c.retryHint(resp.Header))
	case resp.StatusCode >= 500:
		return domain.OktaToken{}, domain.NewTransient(fmt.Errorf("okta server error (%d)", resp.StatusCode), 0)
	}

	var tr tokenResponse
	jsonErr := json.Unmarshal(body, &tr)
	if resp.StatusCode != http.StatusOK {
		code := sanitizeCode(tr.Error)
		if jsonErr != nil {
			code = "unparsable"
		}
		return domain.OktaToken{}, classifyRejection(resp.StatusCode, code)
	}
	if jsonErr != nil {
		return domain.OktaToken{}, domain.Wrap(domain.ErrProvider, errors.New("malformed token response"))
	}
	secs, convErr := strconv.ParseInt(tr.ExpiresIn.String(), 10, 64)
	switch {
	case tr.AccessToken == "":
		return domain.OktaToken{}, domain.Wrap(domain.ErrProvider, errors.New("token response without access_token"))
	case convErr != nil || secs <= 0:
		// ASSUMPTION(A-02): lifetime always comes from the response; there is no default TTL.
		return domain.OktaToken{}, domain.Wrap(domain.ErrProvider, errors.New("token response without a positive expires_in"))
	}
	scope := tr.Scope
	if scope == "" {
		scope = req.Scope
	}
	return domain.OktaToken{
		AccessToken: domain.NewSecret(tr.AccessToken),
		TokenType:   tr.TokenType,
		IssuedAt:    issuedAt,
		ExpiresAt:   issuedAt.Add(time.Duration(secs) * time.Second),
		Audience:    as.Audience,
		Scope:       scope,
		JTI:         a.JTI,
	}, nil
}

func transportErr(ctx context.Context, err error) error {
	if cerr := ctx.Err(); cerr != nil && errors.Is(cerr, context.Canceled) {
		return cerr
	}
	// Do not echo err: url.Error carries the request URL only, but keep the
	// text generic so nothing request related can reach logs.
	if errors.Is(err, context.DeadlineExceeded) {
		return domain.NewTransient(errors.New("okta request timed out"), 0)
	}
	return domain.NewTransient(errors.New("okta request failed"), 0)
}

// retryHint derives a delay from X-Rate-Limit-Reset (epoch seconds, PRD 6.4)
// or Retry-After (seconds). It is clamped to [1 s, 10 min]; 0 means no hint.
func (c *Client) retryHint(h http.Header) time.Duration {
	var d time.Duration
	if v := h.Get("X-Rate-Limit-Reset"); v != "" {
		if epoch, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			d = time.Unix(epoch, 0).Sub(c.clock.Now())
		} else {
			return 0
		}
	} else if v := h.Get("Retry-After"); v != "" {
		secs, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return 0
		}
		d = time.Duration(secs) * time.Second
	} else {
		return 0
	}
	return min(max(d, minRetryHint), maxRetryHint)
}

// definitive lists the Okta rejections that FR-6 treats as "the agent was
// switched off" (after confirmation by the caller). Only codes that identify the
// client qualify; an inactive client is reported by Okta as invalid_client.
// access_denied and invalid_grant can be a per-provider authorization-server
// policy or scope denial, so they stay ErrProvider (FR-R02, assumption A-20).
var definitive = map[string]bool{
	"invalid_client":      true,
	"unauthorized_client": true,
}

func classifyRejection(status int, code string) error {
	if definitive[code] {
		return domain.Wrap(domain.ErrAuthDefinitive, fmt.Errorf("okta rejected the client: %s (http %d)", code, status))
	}
	return domain.Wrap(domain.ErrProvider, fmt.Errorf("okta token request failed: %s (http %d)", code, status))
}

// sanitizeCode keeps only a short lowercase OAuth error code so attacker or
// server controlled text never reaches an error message.
func sanitizeCode(s string) string {
	if s == "" || len(s) > 64 {
		return "unknown"
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && r != '_' {
			return "unknown"
		}
	}
	return s
}

// ErrClockSkew marks a local clock too far from Okta's (FR-9). It wraps
// domain.ErrProvider so ErrorClass reports "provider".
var ErrClockSkew = domain.Wrap(domain.ErrProvider, errors.New("clock skew too large"))

// CheckSkew queries the Okta org with a HEAD request and compares the Date
// header with the local clock (FR-9). It returns the measured skew (server
// minus local, 1 s resolution); the error wraps ErrClockSkew when the
// absolute skew is MaxClockSkew or more. Any HTTP status is acceptable: only
// the Date header matters.
func (c *Client) CheckSkew(ctx context.Context) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.org, nil)
	if err != nil {
		return 0, domain.Wrap(domain.ErrConfig, errors.New("cannot build skew request"))
	}
	before := c.clock.Now()
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, transportErr(ctx, err)
	}
	_ = resp.Body.Close()
	after := c.clock.Now()
	server, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		return 0, domain.Wrap(domain.ErrProvider, errors.New("okta response has no valid Date header"))
	}
	local := before.Add(after.Sub(before) / 2)
	skew := server.Sub(local)
	if skew <= -MaxClockSkew || skew >= MaxClockSkew {
		return skew, fmt.Errorf("%w: %s", ErrClockSkew, skew.Round(time.Second))
	}
	return skew, nil
}
