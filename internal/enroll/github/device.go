package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	ghprov "github.com/stainedhead/agent-okta-d/internal/provider/github"
)

// DefaultScope is the OAuth scope set requested by the device flow (PRD 7.2).
const DefaultScope = "repo read:org workflow"

const (
	deviceGrant   = "urn:ietf:params:oauth:grant-type:device_code"
	slowDownStep  = 5 * time.Second // RFC 8628 section 3.5
	defaultPoll   = 5 * time.Second
	maxFlowBodies = 1 << 20
)

// DeviceOptions tunes the device flow.
type DeviceOptions struct {
	Scope string // OAuth scopes; DefaultScope when empty
}

type deviceCode struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Error           string `json:"error"`
	ErrorDesc       string `json:"error_description"`
}

type tokenResp struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// EnrollDevice runs the OAuth device flow (RFC 8628, GH-5) against the
// configured oauth_client_id (ASSUMPTION(A-06): default is the GitHub CLI's
// public app), prints the user code and URL to o.Out, polls on the injected
// clock, verifies the token belongs to providers.github.login and stores it.
func EnrollDevice(ctx context.Context, o Options, d DeviceOptions) (Result, error) {
	cfg := o.Provider.Config()
	if cfg.Mode != ghprov.ModeOAuthDevice {
		return Result{}, domain.NewConfigError("providers.github.mode", "enroll github --mode oauth_device requires mode: oauth_device")
	}
	scope := d.Scope
	if scope == "" {
		scope = DefaultScope
	}
	web := ghprov.WebBase(cfg.APIBase)
	dc, err := requestCode(ctx, cfg, web, scope)
	if err != nil {
		return Result{}, err
	}
	clk := o.Deps.Clock()
	deadline := clk.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)
	if o.Out != nil {
		_, _ = fmt.Fprintf(o.Out, "Open %s and enter the code %s as %s.\nWaiting for approval...\n", dc.VerificationURI, dc.UserCode, cfg.Login)
	}
	interval := time.Duration(dc.Interval) * time.Second
	if interval <= 0 {
		interval = defaultPoll
	}
	tok, err := poll(ctx, cfg, web, dc.DeviceCode, interval, deadline, clk)
	if err != nil {
		return Result{}, err
	}
	secret := domain.NewSecret(tok.AccessToken)
	u, err := verify(ctx, o, secret)
	if err != nil {
		return Result{}, err
	}
	res := Result{Login: u.Login, UserID: u.ID}
	res.Version, err = save(ctx, o, ghprov.Stored{Mode: ghprov.ModeOAuthDevice, Token: tok.AccessToken, Scope: tok.Scope})
	return res, err
}

func postForm(ctx context.Context, cfg ghprov.Config, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return domain.NewConfigError("providers.github.api_base", "invalid URL")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "agent-okta-d")
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return domain.NewTransient(fmt.Errorf("device flow request failed: %w", err), 0)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFlowBodies))
	if err != nil {
		return domain.NewTransient(errors.New("reading device flow response"), 0)
	}
	if resp.StatusCode >= 500 {
		return domain.NewTransient(fmt.Errorf("github returned %d", resp.StatusCode), 0)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return domain.NewProviderError(ghprov.ProviderName, fmt.Errorf("unreadable device flow response (HTTP %d)", resp.StatusCode))
	}
	return nil
}

func requestCode(ctx context.Context, cfg ghprov.Config, web, scope string) (deviceCode, error) {
	var dc deviceCode
	err := postForm(ctx, cfg, web+"/login/device/code", url.Values{"client_id": {cfg.OAuthClientID}, "scope": {scope}}, &dc)
	switch {
	case err != nil:
		return dc, err
	case dc.Error != "":
		return dc, flowError("device code request", dc.Error, dc.ErrorDesc)
	case dc.DeviceCode == "" || dc.UserCode == "" || dc.VerificationURI == "" || dc.ExpiresIn <= 0:
		return dc, domain.NewProviderError(ghprov.ProviderName, errors.New("incomplete device code response"))
	}
	return dc, nil
}

func flowError(what, code, desc string) error {
	msg := what + ": " + code
	if desc != "" {
		msg += " (" + desc + ")"
	}
	switch code {
	case "access_denied":
		return domain.Wrap(domain.ErrAuthDefinitive, errors.New("the operator denied the device authorization"))
	case "expired_token":
		return domain.NewProviderError(ghprov.ProviderName, errors.New("device code expired before approval"))
	}
	return domain.NewProviderError(ghprov.ProviderName, errors.New(msg))
}

func poll(ctx context.Context, cfg ghprov.Config, web, deviceCode string, interval time.Duration, deadline time.Time, clk domain.Clock) (tokenResp, error) {
	form := url.Values{"client_id": {cfg.OAuthClientID}, "device_code": {deviceCode}, "grant_type": {deviceGrant}}
	for {
		t := clk.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return tokenResp{}, ctx.Err()
		case <-t.C():
		}
		if !clk.Now().Before(deadline) {
			return tokenResp{}, domain.NewProviderError(ghprov.ProviderName, errors.New("device code expired before approval"))
		}
		var tr tokenResp
		err := postForm(ctx, cfg, web+"/login/oauth/access_token", form, &tr)
		switch {
		case errors.Is(err, domain.ErrTransient):
			continue // keep polling until the device code expires
		case err != nil:
			return tokenResp{}, err
		}
		switch tr.Error {
		case "":
			if tr.AccessToken == "" {
				return tokenResp{}, domain.NewProviderError(ghprov.ProviderName, errors.New("device flow returned no access token"))
			}
			return tr, nil
		case "authorization_pending":
		case "slow_down":
			interval += slowDownStep
		default:
			return tokenResp{}, flowError("device flow", tr.Error, tr.ErrorDesc)
		}
	}
}
