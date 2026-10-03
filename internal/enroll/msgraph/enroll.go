// Package msgraph implements `agent-okta-d enroll msgraph` (PRD 7.5): the
// OAuth device-code flow against the shared public-client app. An operator
// signs in as the agent user once; the resulting refresh token goes into the
// configured SecretStore. Tokens are never printed or logged.
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
	"strings"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

const (
	defaultLoginBase = "https://login.microsoftonline.com"
	defaultGraphBase = "https://graph.microsoft.com/v1.0"
	deviceGrant      = "urn:ietf:params:oauth:grant-type:device_code"
	defaultInterval  = 5 * time.Second
	slowDownStep     = 5 * time.Second
	maxBody          = 1 << 20
)

// Config configures one enrollment. LoginBase, GraphBase and HTTP exist so
// tests use httptest servers; production leaves them empty.
type Config struct {
	TenantID string
	ClientID string
	Scopes   []string // must include offline_access
	// ExpectedUPN, when set, is checked against GET /me before anything is
	// stored, so a human cannot enroll their own account by mistake.
	ExpectedUPN string
	Store       domain.SecretStore
	SecretID    string
	Clock       domain.Clock
	Out         io.Writer // operator instructions; nil discards
	LoginBase   string
	GraphBase   string
	HTTP        *http.Client
}

type deviceCode struct {
	DeviceCode      string      `json:"device_code"`
	UserCode        string      `json:"user_code"`
	VerificationURI string      `json:"verification_uri"`
	ExpiresIn       json.Number `json:"expires_in"`
	Interval        json.Number `json:"interval"`
	Message         string      `json:"message"`
}

type tokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
}

// Enroll runs the device-code flow and stores the refresh token.
func Enroll(ctx context.Context, cfg Config) error {
	if err := validate(cfg); err != nil {
		return err
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
	if cfg.Out == nil {
		cfg.Out = io.Discard
	}
	base := strings.TrimRight(cfg.LoginBase, "/") + "/" + cfg.TenantID + "/oauth2/v2.0/"

	dc, err := requestDeviceCode(ctx, cfg, base)
	if err != nil {
		return err
	}
	deadline := cfg.Clock.Now().Add(secs(dc.ExpiresIn, 900))
	interval := secs(dc.Interval, int64(defaultInterval/time.Second))
	_, _ = fmt.Fprintf(cfg.Out, "To enroll, open %s and enter the code %s while signed in AS THE AGENT USER.\nWaiting for sign-in...\n",
		dc.VerificationURI, dc.UserCode)

	for {
		if err := wait(ctx, cfg.Clock, interval); err != nil {
			return err
		}
		if !cfg.Clock.Now().Before(deadline) {
			return domain.Wrap(domain.ErrReauthRequired, errors.New("device code expired before sign-in completed"))
		}
		tr, status, err := pollToken(ctx, cfg, base, dc.DeviceCode)
		if err != nil {
			return err
		}
		if status == http.StatusOK && tr.RefreshToken != "" {
			return finish(ctx, cfg, tr)
		}
		if status == http.StatusOK {
			return domain.Wrap(domain.ErrProvider, errors.New("no refresh token returned; offline_access was not granted"))
		}
		switch {
		case tr.Error == "authorization_pending":
		case tr.Error == "slow_down":
			interval += slowDownStep
		case status >= 500 || status == http.StatusTooManyRequests:
			return domain.NewTransient(fmt.Errorf("token endpoint status %d", status), 0)
		case tr.Error == "authorization_declined" || tr.Error == "access_denied" || tr.Error == "expired_token" || tr.Error == "bad_verification_code":
			return domain.Wrap(domain.ErrReauthRequired, fmt.Errorf("sign-in not completed (%s)", tr.Error))
		case tr.Error == "invalid_client" || tr.Error == "unauthorized_client" || tr.Error == "invalid_scope":
			return domain.Wrap(domain.ErrConfig, fmt.Errorf("token endpoint rejected app configuration (%s)", tr.Error))
		default:
			return domain.Wrap(domain.ErrProvider, fmt.Errorf("token endpoint status %d", status))
		}
	}
}

func validate(cfg Config) error {
	switch {
	case cfg.TenantID == "" || strings.ContainsAny(cfg.TenantID, "/?#"):
		return domain.NewConfigError("msgraph.tenant_id", "required and must be a plain tenant id")
	case cfg.ClientID == "":
		return domain.NewConfigError("msgraph.app_client_id", "required")
	case !slices.Contains(cfg.Scopes, "offline_access"):
		return domain.NewConfigError("msgraph.scopes", "must include offline_access")
	case cfg.Store == nil:
		return domain.NewConfigError("msgraph.store", "required")
	case cfg.SecretID == "":
		return domain.NewConfigError("msgraph.store.secret_id", "required")
	case cfg.Clock == nil:
		return domain.NewConfigError("clock", "required")
	}
	return nil
}

func requestDeviceCode(ctx context.Context, cfg Config, base string) (deviceCode, error) {
	var dc deviceCode
	status, body, err := post(ctx, cfg.HTTP, base+"devicecode", url.Values{
		"client_id": {cfg.ClientID}, "scope": {strings.Join(cfg.Scopes, " ")},
	})
	switch {
	case err != nil:
		return dc, domain.NewTransient(fmt.Errorf("devicecode endpoint: %w", err), 0)
	case status >= 500 || status == http.StatusTooManyRequests:
		return dc, domain.NewTransient(fmt.Errorf("devicecode endpoint status %d", status), 0)
	case status != http.StatusOK:
		return dc, domain.Wrap(domain.ErrProvider, fmt.Errorf("devicecode endpoint status %d", status))
	}
	if json.Unmarshal(body, &dc) != nil || dc.DeviceCode == "" || dc.UserCode == "" || dc.VerificationURI == "" {
		return dc, domain.Wrap(domain.ErrProvider, errors.New("malformed devicecode response"))
	}
	return dc, nil
}

func pollToken(ctx context.Context, cfg Config, base, device string) (tokenResp, int, error) {
	var tr tokenResp
	status, body, err := post(ctx, cfg.HTTP, base+"token", url.Values{
		"grant_type": {deviceGrant}, "client_id": {cfg.ClientID}, "device_code": {device},
	})
	if err != nil {
		return tr, 0, domain.NewTransient(fmt.Errorf("token endpoint: %w", err), 0)
	}
	_ = json.Unmarshal(body, &tr)
	return tr, status, nil
}

// finish verifies the signed-in user (when configured) and stores the refresh
// token with compare-and-set against whatever is currently stored.
func finish(ctx context.Context, cfg Config, tr tokenResp) error {
	if cfg.ExpectedUPN != "" {
		if err := checkUser(ctx, cfg, tr.AccessToken); err != nil {
			return err
		}
	}
	version := ""
	switch cur, err := cfg.Store.Get(ctx, cfg.SecretID); {
	case err == nil:
		version = cur.Version
	case !errors.Is(err, domain.ErrNotFound):
		return domain.NewTransient(errors.New("read existing refresh token"), 0)
	}
	if _, err := cfg.Store.Put(ctx, cfg.SecretID, domain.NewSecret(tr.RefreshToken), version); err != nil {
		if errors.Is(err, domain.ErrVersionConflict) {
			return domain.NewTransient(errors.New("refresh token store changed during enrollment; retry"), 0)
		}
		return domain.Wrap(domain.ErrProvider, errors.New("store refresh token failed"))
	}
	_, _ = fmt.Fprintln(cfg.Out, "Enrollment complete; refresh token stored.")
	return nil
}

func checkUser(ctx context.Context, cfg Config, access string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cfg.GraphBase, "/")+"/me", nil)
	if err != nil {
		return domain.Wrap(domain.ErrProvider, errors.New("build /me request"))
	}
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := cfg.HTTP.Do(req)
	if err != nil {
		return domain.NewTransient(errors.New("GET /me failed"), 0)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	var me struct {
		UPN string `json:"userPrincipalName"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(b, &me) != nil {
		return domain.Wrap(domain.ErrProvider, fmt.Errorf("GET /me status %d", resp.StatusCode))
	}
	if !strings.EqualFold(me.UPN, cfg.ExpectedUPN) {
		return domain.Wrap(domain.ErrPolicy, fmt.Errorf("signed in as %q, expected the agent user %q; nothing stored", me.UPN, cfg.ExpectedUPN))
	}
	return nil
}

func post(ctx context.Context, c *http.Client, u string, form url.Values) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return resp.StatusCode, b, err
}

func wait(ctx context.Context, clk domain.Clock, d time.Duration) error {
	t := clk.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C():
		return nil
	}
}

func secs(n json.Number, def int64) time.Duration {
	v, err := n.Int64()
	if err != nil || v <= 0 {
		v = def
	}
	return time.Duration(v) * time.Second
}
