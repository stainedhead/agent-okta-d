// Package msgraph implements the delegated Microsoft Graph provider (PRD 7.5,
// MG-1..MG-6): it exchanges a stored refresh token for a short-lived Graph
// access token, persisting any rotated refresh token before the access token
// is returned.
package msgraph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// ProviderName is the provider id used in config, URLs and audit events.
const ProviderName = "msgraph"

// GraphAudience is the audience recorded on minted credentials.
const GraphAudience = "https://graph.microsoft.com"

const (
	defaultLoginBase = "https://login.microsoftonline.com"
	defaultGraphBase = "https://graph.microsoft.com/v1.0"
	maxBody          = 1 << 20
)

// Config configures the provider. LoginBase, GraphBase and HTTP exist so tests
// point at httptest servers; production leaves them empty.
type Config struct {
	TenantID  string
	ClientID  string // shared public-client app
	UPN       string // doctor checks GET /me matches
	Scopes    []string
	StoreName string // Deps.Store name holding the refresh token
	SecretID  string // key of the refresh token inside the store
	// ProbeOtherUser is a mailbox the agent must NOT be able to read; the
	// doctor negative test expects GET /users/{it}/messages to return 403.
	ProbeOtherUser string
	LoginBase      string
	GraphBase      string
	HTTP           *http.Client
}

// Provider is the msgraph domain.Provider.
type Provider struct {
	cfg Config
}

var _ domain.Provider = (*Provider)(nil)

// New validates cfg and builds a Provider.
func New(cfg Config) (*Provider, error) {
	switch {
	case cfg.TenantID == "" || strings.ContainsAny(cfg.TenantID, "/?#"):
		return nil, domain.NewConfigError("msgraph.tenant_id", "required and must be a plain tenant id")
	case cfg.ClientID == "":
		return nil, domain.NewConfigError("msgraph.app_client_id", "required")
	case cfg.UPN == "":
		return nil, domain.NewConfigError("msgraph.upn", "required")
	case len(cfg.Scopes) == 0:
		return nil, domain.NewConfigError("msgraph.scopes", "required")
	case !slices.Contains(cfg.Scopes, "offline_access"):
		return nil, domain.NewConfigError("msgraph.scopes", "must include offline_access")
	case cfg.StoreName == "":
		return nil, domain.NewConfigError("msgraph.store", "required")
	case cfg.SecretID == "":
		return nil, domain.NewConfigError("msgraph.store.secret_id", "required")
	}
	if cfg.LoginBase == "" {
		cfg.LoginBase = defaultLoginBase
	}
	if cfg.GraphBase == "" {
		cfg.GraphBase = defaultGraphBase
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	cfg.HTTP = domain.NoRedirect(cfg.HTTP) // FR-R08
	cfg.LoginBase = strings.TrimRight(cfg.LoginBase, "/")
	cfg.GraphBase = strings.TrimRight(cfg.GraphBase, "/")
	return &Provider{cfg: cfg}, nil
}

// Name implements domain.Provider.
func (*Provider) Name() string { return ProviderName }

// Sinks implements domain.Provider: msgraph has no file sink (MG-4).
func (*Provider) Sinks() []domain.SinkSpec { return nil }

// Revoke implements domain.Provider: user-credential providers have no
// revocation hook; revocation is account-side (PRD 13).
func (*Provider) Revoke(context.Context, domain.Credential) error { return nil }

type tokenResponse struct {
	TokenType    string          `json:"token_type"`
	AccessToken  string          `json:"access_token"`
	RefreshToken string          `json:"refresh_token"`
	ExpiresIn    json.RawMessage `json:"expires_in"`
	Scope        string          `json:"scope"`
}

type oauthError struct {
	Error string `json:"error"`
}

// Mint implements domain.Provider (MG-1, MG-2, MG-5).
func (p *Provider) Mint(ctx context.Context, d domain.Deps) (domain.Credential, error) {
	store, err := d.Store(p.cfg.StoreName)
	if err != nil {
		return domain.Credential{}, err
	}
	stored, err := store.Get(ctx, p.cfg.SecretID)
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return domain.Credential{}, domain.Wrap(domain.ErrReauthRequired, errors.New("no refresh token stored; run enroll msgraph"))
	case err != nil:
		return domain.Credential{}, transient("read refresh token store", err)
	case stored.Value.IsZero():
		return domain.Credential{}, domain.Wrap(domain.ErrReauthRequired, errors.New("stored refresh token is empty; run enroll msgraph"))
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {p.cfg.ClientID},
		"refresh_token": {stored.Value.Reveal()},
		"scope":         {strings.Join(p.cfg.Scopes, " ")},
	}
	status, hdr, body, err := p.postForm(ctx, p.cfg.LoginBase+"/"+p.cfg.TenantID+"/oauth2/v2.0/token", form)
	if err != nil {
		return domain.Credential{}, transient("token endpoint", err)
	}
	if status != http.StatusOK {
		return domain.Credential{}, mapTokenError(status, hdr, body)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return domain.Credential{}, domain.Wrap(domain.ErrProvider, errors.New("malformed token response"))
	}
	secs, ok := parseExpires(tr.ExpiresIn)
	if !ok || secs <= 0 {
		return domain.Credential{}, domain.Wrap(domain.ErrProvider, errors.New("token response without a positive expires_in"))
	}

	// MG-2: persist the rotated refresh token BEFORE the access token leaves
	// this function. If we cannot persist, withhold the access token.
	if tr.RefreshToken != "" && tr.RefreshToken != stored.Value.Reveal() {
		_, perr := store.Put(ctx, p.cfg.SecretID, domain.NewSecret(tr.RefreshToken), stored.Version)
		switch {
		case perr == nil:
		case errors.Is(perr, domain.ErrVersionConflict):
			return domain.Credential{}, domain.NewTransient(fmt.Errorf("refresh token store version conflict: %w", perr), 0)
		default:
			return domain.Credential{}, domain.Wrap(domain.ErrProvider, errors.New("persist rotated refresh token failed (access token withheld)"))
		}
	}

	now := d.Clock().Now()
	scope := tr.Scope
	if scope == "" {
		scope = strings.Join(p.cfg.Scopes, " ")
	}
	return domain.Credential{
		Kind:      domain.KindBearer,
		Value:     domain.NewSecret(tr.AccessToken),
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Duration(secs) * time.Second),
		Meta:      map[string]string{domain.MetaAudience: GraphAudience, domain.MetaScope: scope, domain.MetaLogin: p.cfg.UPN},
	}, nil
}

// mapTokenError classifies a non-200 token endpoint answer. ASSUMPTION(A-07):
// every invalid_grant variant (disabled user, password reset, CAE, sign-in
// frequency, expired refresh token) maps to reauth_required, never to
// ErrAuthDefinitive, so the daemon never enters revoked because of Entra.
func mapTokenError(status int, hdr http.Header, body []byte) error {
	if status >= 500 || status == http.StatusTooManyRequests || status == http.StatusRequestTimeout {
		return domain.NewTransient(fmt.Errorf("token endpoint status %d", status), retryAfter(hdr))
	}
	var oe oauthError
	_ = json.Unmarshal(body, &oe) // the error code is a fixed OAuth token; descriptions are never surfaced
	switch oe.Error {
	case "invalid_grant", "interaction_required", "consent_required", "login_required":
		return domain.Wrap(domain.ErrReauthRequired, fmt.Errorf("token endpoint rejected refresh token (%s)", oe.Error))
	case "invalid_client", "unauthorized_client", "invalid_scope":
		return domain.Wrap(domain.ErrConfig, fmt.Errorf("token endpoint rejected app configuration (%s)", oe.Error))
	}
	return domain.Wrap(domain.ErrProvider, fmt.Errorf("token endpoint status %d", status))
}

// Probe implements domain.Provider (MG-6).
func (p *Provider) Probe(ctx context.Context, c domain.Credential) error {
	if c.Value.IsZero() {
		return domain.Wrap(domain.ErrProvider, errors.New("probe without access token"))
	}
	if p.cfg.ProbeOtherUser == "" {
		return domain.NewConfigError("msgraph.probe_other_user", "required for the cross-mailbox negative test")
	}
	status, _, body, err := p.graphGet(ctx, c, "/me")
	if err := probeStatus("GET /me", status, err); err != nil {
		return err
	}
	var me struct {
		UPN string `json:"userPrincipalName"`
	}
	if jerr := json.Unmarshal(body, &me); jerr != nil {
		return domain.Wrap(domain.ErrProvider, errors.New("GET /me: malformed response"))
	}
	if !strings.EqualFold(me.UPN, p.cfg.UPN) {
		return domain.Wrap(domain.ErrPolicy, fmt.Errorf("GET /me returned UPN %q, expected %q", me.UPN, p.cfg.UPN))
	}
	for _, path := range []string{"/me/mailFolders/inbox", "/me/chats?$top=1"} {
		status, _, _, err = p.graphGet(ctx, c, path)
		if err := probeStatus("GET "+path, status, err); err != nil {
			return err
		}
	}
	// Negative test: the delegated token must not reach another mailbox.
	status, _, _, err = p.graphGet(ctx, c, "/users/"+url.PathEscape(p.cfg.ProbeOtherUser)+"/messages")
	switch {
	case err != nil:
		return transient("cross-mailbox probe", err)
	case status == http.StatusForbidden:
		return nil
	case status >= 500 || status == http.StatusTooManyRequests:
		return domain.NewTransient(fmt.Errorf("cross-mailbox probe status %d", status), 0)
	case status >= 200 && status < 300:
		return domain.Wrap(domain.ErrPolicy, errors.New("cross-mailbox read succeeded; agent user can reach another mailbox"))
	}
	return domain.Wrap(domain.ErrProvider, fmt.Errorf("cross-mailbox probe expected 403, got %d", status))
}

func probeStatus(what string, status int, err error) error {
	switch {
	case err != nil:
		return transient(what, err)
	case status >= 500 || status == http.StatusTooManyRequests:
		return domain.NewTransient(fmt.Errorf("%s status %d", what, status), 0)
	case status < 200 || status >= 300:
		return domain.Wrap(domain.ErrProvider, fmt.Errorf("%s status %d", what, status))
	}
	return nil
}

func (p *Provider) graphGet(ctx context.Context, c domain.Credential, path string) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.GraphBase+path, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Value.Reveal())
	req.Header.Set("Accept", "application/json")
	return p.do(req)
}

func (p *Provider) postForm(ctx context.Context, u string, form url.Values) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return p.do(req)
}

func (p *Provider) do(req *http.Request) (int, http.Header, []byte, error) {
	resp, err := p.cfg.HTTP.Do(req)
	if err != nil {
		return 0, nil, nil, redactURLError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return 0, nil, nil, err
	}
	return resp.StatusCode, resp.Header, b, nil
}

// redactURLError drops the request URL (which may carry a mailbox name) from
// transport errors and keeps only the cause.
func redactURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func transient(what string, err error) error {
	return domain.NewTransient(fmt.Errorf("%s: %w", what, err), 0)
}

func parseExpires(raw json.RawMessage) (int64, bool) {
	s := strings.Trim(string(raw), `"`)
	if s == "" || s == "null" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

func retryAfter(h http.Header) time.Duration {
	if n, err := strconv.Atoi(strings.TrimSpace(h.Get("Retry-After"))); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 0
}
