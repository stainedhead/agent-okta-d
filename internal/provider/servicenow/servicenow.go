// Package servicenow implements the ServiceNow provider (PRD 7.3, SN-1..SN-4).
// ServiceNow validates the Okta access token itself, so the daemon only mints
// an Okta token for the agents-snow authorization server and hands it out as a
// Bearer credential. The token is never written to disk (SN-2: no sinks).
package servicenow

import (
	"context"
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

// ProviderName is the provider id used in config, URLs and audit events.
const ProviderName = "servicenow"

// DefaultMinTTL is the PRD default for min_ttl_seconds (SN-3).
const DefaultMinTTL = 120 * time.Second

// DefaultWhoamiPath is the probe endpoint used when Config.WhoamiPath is
// empty. NEW ASSUMPTION (proposed id A-13, not yet in docs/assumptions.md):
// the PRD only says "the snow whoami endpoint (see companion PRD)" and the
// companion PRD is not in this repo, so the real path is unconfirmed. The
// default is the standard Table API read of the calling user's own record,
// and the path is configurable. Any 2xx counts as success; the body is not
// interpreted.
const DefaultWhoamiPath = "/api/now/table/sys_user?sysparm_limit=1&sysparm_fields=user_name"

// ErrRejected marks a 401/403 from the instance: the token was refused, which
// for a valid Okta token means the sys_user is deactivated or unmapped (the
// PRD 13 kill switch for ServiceNow). Errors wrapping it also match
// domain.ErrProvider.
var ErrRejected = errors.New("servicenow rejected the token")

// Config is the providers.servicenow section.
type Config struct {
	InstanceURL string        // https://EXAMPLE.service-now.com
	AuthServer  string        // okta authorization_server config name, for example agents-snow
	Scope       string        // for example snow.agent
	MinTTL      time.Duration // min_ttl_seconds; 0 means DefaultMinTTL
	WhoamiPath  string        // optional, starts with "/"
	HTTPClient  *http.Client  // optional; defaults to a client with a 10 s timeout
}

// Provider is the ServiceNow domain.Provider.
type Provider struct {
	base       string
	authServer string
	scope      string
	minTTL     time.Duration
	whoami     string
	hc         *http.Client
}

// New validates cfg. Problems are domain.ErrConfig.
func New(cfg Config) (*Provider, error) {
	u, err := url.Parse(cfg.InstanceURL)
	switch {
	case cfg.InstanceURL == "" || err != nil || u.Hostname() == "":
		return nil, domain.NewConfigError("providers.servicenow.instance_url", "must be an absolute URL")
	case u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())):
		return nil, domain.NewConfigError("providers.servicenow.instance_url", "must use https")
	case cfg.AuthServer == "":
		return nil, domain.NewConfigError("providers.servicenow.authorization_server", "is required")
	case cfg.Scope == "":
		return nil, domain.NewConfigError("providers.servicenow.scope", "is required")
	case cfg.MinTTL < 0:
		return nil, domain.NewConfigError("providers.servicenow.min_ttl_seconds", "must not be negative")
	case cfg.WhoamiPath != "" && !strings.HasPrefix(cfg.WhoamiPath, "/"):
		return nil, domain.NewConfigError("providers.servicenow.whoami_path", "must start with /")
	}
	p := &Provider{
		base: strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/"), authServer: cfg.AuthServer, scope: cfg.Scope,
		minTTL: cfg.MinTTL, whoami: cfg.WhoamiPath, hc: cfg.HTTPClient,
	}
	if p.minTTL == 0 {
		p.minTTL = DefaultMinTTL
	}
	if p.whoami == "" {
		p.whoami = DefaultWhoamiPath
	}
	if p.hc == nil {
		p.hc = &http.Client{Timeout: 10 * time.Second}
	}
	return p, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Name implements domain.Provider.
func (*Provider) Name() string { return ProviderName }

// Sinks implements domain.Provider. SN-2: the token is never written to disk.
func (*Provider) Sinks() []domain.SinkSpec { return nil }

// Revoke implements domain.Provider. ServiceNow holds no daemon-side state;
// cut-off is deactivating the sys_user (PRD 13), so there is nothing to do.
func (*Provider) Revoke(context.Context, domain.Credential) error { return nil }

// MinTTL is the configured min_ttl_seconds.
func (p *Provider) MinTTL() time.Duration { return p.minTTL }

// Mint implements domain.Provider (SN-1): an Okta access token from the
// agents-snow authorization server, served as a Bearer credential.
func (p *Provider) Mint(ctx context.Context, d domain.Deps) (domain.Credential, error) {
	tok, err := d.Okta().Token(ctx, domain.OktaTokenRequest{AuthServer: p.authServer, Scope: p.scope})
	if err != nil {
		return domain.Credential{}, err
	}
	scope := tok.Scope
	if scope == "" {
		scope = p.scope
	}
	c := domain.Credential{
		Kind: domain.KindBearer, Value: tok.AccessToken,
		// ASSUMPTION(A-02): lifetime is taken from the Okta response, never hardcoded.
		IssuedAt: tok.IssuedAt, ExpiresAt: tok.ExpiresAt,
		Meta: map[string]string{domain.MetaAudience: tok.Audience, domain.MetaScope: scope},
	}
	if tok.JTI != "" {
		c.Meta[domain.MetaJTI] = tok.JTI
	}
	if err := c.Validate(); err != nil {
		return domain.Credential{}, domain.NewProviderError(ProviderName, err)
	}
	if c.Expired(d.Clock().Now()) {
		return domain.Credential{}, domain.NewProviderError(ProviderName, errors.New("okta returned an already expired token"))
	}
	return c, nil
}

// NeedsRefresh implements SN-3: true when less than min_ttl remains at now (or
// c is not a usable credential).
func (p *Provider) NeedsRefresh(c domain.Credential, now time.Time) bool {
	return c.Validate() != nil || c.Remaining(now) < p.minTTL
}

// Fresh returns c while at least min_ttl remains, otherwise it mints a new
// credential synchronously (SN-3). A mint failure is returned as is: a
// credential below min_ttl is never served in its place.
func (p *Provider) Fresh(ctx context.Context, d domain.Deps, c domain.Credential) (domain.Credential, error) {
	if !p.NeedsRefresh(c, d.Clock().Now()) {
		return c, nil
	}
	return p.Mint(ctx, d)
}

// Probe implements domain.Provider (SN-4): call the whoami endpoint with the
// token. 401/403 (typically a deactivated sys_user) is ErrProvider wrapping
// ErrRejected; 429, 5xx and network errors are transient.
func (p *Provider) Probe(ctx context.Context, c domain.Credential) error {
	if c.Value.IsZero() {
		return domain.NewProviderError(ProviderName, errors.New("empty credential"))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base+p.whoami, nil)
	if err != nil {
		return domain.NewProviderError(ProviderName, errors.New("invalid whoami request"))
	}
	req.Header.Set("Authorization", "Bearer "+c.Value.Reveal())
	req.Header.Set("Accept", "application/json")
	resp, err := p.hc.Do(req)
	if err != nil {
		// url.Error carries only the URL, never headers; drop it anyway to be safe.
		return domain.NewTransient(fmt.Errorf("servicenow whoami: %s", transportReason(err)), 0)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	switch s := resp.StatusCode; {
	case s >= 200 && s < 300:
		return nil
	case s == http.StatusUnauthorized || s == http.StatusForbidden:
		return fmt.Errorf("%w: %w: whoami returned %d (sys_user deactivated, unmapped or token invalid)", domain.ErrProvider, ErrRejected, s)
	case s == http.StatusTooManyRequests || s >= 500:
		return domain.NewTransient(fmt.Errorf("servicenow whoami returned %d", s), retryAfter(resp))
	default:
		return domain.NewProviderError(ProviderName, fmt.Errorf("whoami returned %d", s))
	}
}

func transportReason(err error) string {
	var ue interface{ Unwrap() error }
	if errors.As(err, &ue) && ue.Unwrap() != nil {
		return ue.Unwrap().Error()
	}
	return err.Error()
}

func retryAfter(resp *http.Response) time.Duration {
	if n, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 0
}
