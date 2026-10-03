package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// ExpiryHeader is the response header that carries a PAT expiry.
// ASSUMPTION(A-05): the header name and its time format are unconfirmed; the
// value is optional and an unparsable value is ignored.
const ExpiryHeader = "github-authentication-token-expiration"

const maxBody = 1 << 20

// API is a minimal GitHub REST client for the calls the daemon needs.
type API struct {
	Base string // for example https://api.github.com
	HTTP *http.Client
	Now  func() time.Time // for Retry-After arithmetic; time.Now when nil
}

// User is the GET /user result.
type User struct {
	ID          int64
	Login       string
	TokenExpiry time.Time // from ExpiryHeader, zero when absent (A-05)
}

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *API) get(ctx context.Context, token domain.SecretString, path string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(a.Base, "/")+path, nil)
	if err != nil {
		return nil, nil, domain.Wrap(domain.ErrConfig, errors.New("invalid github api_base"))
	}
	req.Header.Set("Authorization", "Bearer "+token.Reveal())
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "agent-okta-d")
	hc := domain.NoRedirect(a.HTTP) // FR-R08
	resp, err := hc.Do(req)
	if err != nil {
		// url.Error text holds the URL only, never headers.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, nil, domain.NewTransient(fmt.Errorf("github request failed: %w", err), 0)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, nil, domain.NewTransient(errors.New("reading github response"), 0)
	}
	if cerr := a.classify(resp); cerr != nil {
		return resp, body, cerr
	}
	return resp, body, nil
}

// classify maps a status to the error taxonomy (GH-9): 401 means the stored
// credential is rejected; 403/429 rate limits surface their retry hint; 5xx
// is transient; other failures are provider errors.
func (a *API) classify(resp *http.Response) error {
	code := resp.StatusCode
	switch {
	case code >= 200 && code < 300:
		return nil
	case code == http.StatusUnauthorized:
		return domain.Wrap(domain.ErrReauthRequired, errors.New("github rejected the token (401)"))
	case code == http.StatusTooManyRequests:
		return domain.NewTransient(errors.New("github rate limited (429)"), a.retryHint(resp))
	case code == http.StatusForbidden:
		if h := a.retryHint(resp); h > 0 || resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return domain.NewTransient(errors.New("github rate limited (403)"), h)
		}
		return domain.NewProviderError(ProviderName, errors.New("github forbade the request (403)"))
	case code >= 500:
		return domain.NewTransient(fmt.Errorf("github server error (%d)", code), a.retryHint(resp))
	}
	return domain.NewProviderError(ProviderName, fmt.Errorf("unexpected github status %d", code))
}

func (a *API) retryHint(resp *http.Response) time.Duration {
	if v := resp.Header.Get("Retry-After"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
		if t, err := http.ParseTime(v); err == nil {
			return max(t.Sub(a.now()), 0)
		}
	}
	if v := resp.Header.Get("X-RateLimit-Reset"); v != "" && resp.Header.Get("X-RateLimit-Remaining") == "0" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return max(time.Unix(n, 0).Sub(a.now()), 0)
		}
	}
	return 0
}

// User calls GET /user with token.
func (a *API) User(ctx context.Context, token domain.SecretString) (User, error) {
	resp, body, err := a.get(ctx, token, "/user")
	if err != nil {
		return User{}, err
	}
	var w struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	}
	if err := json.Unmarshal(body, &w); err != nil || w.Login == "" || w.ID == 0 {
		return User{}, domain.NewProviderError(ProviderName, errors.New("malformed GET /user response"))
	}
	u := User{ID: w.ID, Login: w.Login}
	if t, ok := ParseExpiryHeader(resp.Header.Get(ExpiryHeader)); ok {
		u.TokenExpiry = t
	}
	return u, nil
}

// Repo performs a read on owner/name (GH-7).
func (a *API) Repo(ctx context.Context, token domain.SecretString, ownerName string) error {
	_, _, err := a.get(ctx, token, "/repos/"+ownerName)
	return err
}

// ParseExpiryHeader parses the PAT expiry header value (A-05).
func ParseExpiryHeader(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	for _, layout := range []string{"2006-01-02 15:04:05 MST", "2006-01-02 15:04:05 -0700", time.RFC3339} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
