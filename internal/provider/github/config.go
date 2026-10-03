package github

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// Defaults.
const (
	// DefaultAPIBase is the github.com REST endpoint (GH-10 makes it configurable).
	DefaultAPIBase = "https://api.github.com"
	// DefaultRefetchInterval is how often the cache re-reads the secret store (GH-2).
	DefaultRefetchInterval = 15 * time.Minute
	// DefaultOAuthClientID is the GitHub CLI's public OAuth app client id.
	// ASSUMPTION(A-06): the enterprise allows this app for EMU users; operators
	// override it with providers.github.oauth_client_id.
	DefaultOAuthClientID = "178c6fc778ccc68e1d6a"
	// ProviderName is the stable provider id.
	ProviderName = "github"
)

// Config is providers.github (PRD section 14) resolved for the provider.
type Config struct {
	APIBase           string
	Mode              Mode
	Login             string // EMU login; doctor checks GET /user against it (GH-7)
	OAuthClientID     string // oauth_device only
	StoreName         string // name passed to Deps.Store
	SecretID          string // key within the store
	ExpiryWarningDays int
	RefetchInterval   time.Duration // credential horizon between store reads
	GitName           string        // configure git user.name
	GitEmail          string        // configure git user.email; may contain <id> and <login>
	ProbeRepo         string        // optional "owner/name" for the doctor read check (GH-7)
	TokenFile         string        // optional sink path for the raw token
	HTTPClient        *http.Client
}

// Normalize applies defaults and validates; errors are *domain.ConfigError.
func (c Config) Normalize() (Config, error) {
	if c.APIBase == "" {
		c.APIBase = DefaultAPIBase
	}
	c.APIBase = strings.TrimRight(c.APIBase, "/")
	if u, err := url.Parse(c.APIBase); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return c, domain.NewConfigError("providers.github.api_base", "must be an http(s) URL")
	}
	switch {
	case !c.Mode.Valid():
		return c, domain.NewConfigError("providers.github.mode", "must be pat or oauth_device")
	case c.Login == "":
		return c, domain.NewConfigError("providers.github.login", "required")
	case c.StoreName == "":
		return c, domain.NewConfigError("providers.github.store", "required")
	case c.SecretID == "":
		return c, domain.NewConfigError("providers.github.store.secret_id", "required")
	case c.ExpiryWarningDays < 0:
		return c, domain.NewConfigError("providers.github.expiry_warning_days", "must not be negative")
	case c.ProbeRepo != "" && strings.Count(c.ProbeRepo, "/") != 1:
		return c, domain.NewConfigError("providers.github.probe_repo", "must be owner/name")
	}
	if c.ExpiryWarningDays == 0 {
		c.ExpiryWarningDays = DefaultExpiryWarningDays
	}
	if c.RefetchInterval <= 0 {
		c.RefetchInterval = DefaultRefetchInterval
	}
	if c.Mode == ModeOAuthDevice && c.OAuthClientID == "" {
		c.OAuthClientID = DefaultOAuthClientID
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	c.HTTPClient = domain.NoRedirect(c.HTTPClient) // FR-R08: tokens and device codes never follow a redirect
	return c, nil
}

// WebBase derives the web origin (device flow, git remotes) from an API base:
// api.github.com -> github.com, <host>/api/v3 (GHES) -> <host>, api.<x>.ghe.com
// -> <x>.ghe.com; anything else keeps its scheme and host.
func WebBase(apiBase string) string {
	u, err := url.Parse(strings.TrimRight(apiBase, "/"))
	if err != nil || u.Host == "" {
		return apiBase
	}
	host := u.Host
	if strings.HasPrefix(host, "api.") && (strings.HasSuffix(host, ".ghe.com") || host == "api.github.com") {
		host = strings.TrimPrefix(host, "api.")
	}
	return u.Scheme + "://" + host
}
