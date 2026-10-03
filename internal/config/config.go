// Package config loads, defaults and validates the agent-okta-d YAML
// configuration (PRD section 10). Every failure wraps domain.ErrConfig (exit
// 78) and names the offending field; secret or user-supplied values are never
// echoed in error text (AC-003).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strconv"

	"go.yaml.in/yaml/v3"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// Config is the root configuration document.
type Config struct {
	Agent     Agent     `yaml:"agent"`
	Okta      Okta      `yaml:"okta"`
	Providers Providers `yaml:"providers"`
	Refresh   Refresh   `yaml:"refresh"`
	IPC       IPC       `yaml:"ipc"`
	Log       Log       `yaml:"log"`
}

// Agent identifies the agent.
type Agent struct {
	ID          string `yaml:"id"`
	Environment string `yaml:"environment"`
}

// Okta holds the per-agent API Services app settings.
type Okta struct {
	OrgURL   string `yaml:"org_url"`
	ClientID string `yaml:"client_id"`
	Signer   Signer `yaml:"signer"`
}

// Signer selects the key holder. For type "file" KeyID is the private key path.
type Signer struct {
	Type  string `yaml:"type"`
	KeyID string `yaml:"key_id"`
	Alg   string `yaml:"alg"`
	KID   string `yaml:"kid"`
}

// Providers holds optional per-provider sections; nil means not configured.
type Providers struct {
	AWS        *AWS        `yaml:"aws"`
	GitHub     *GitHub     `yaml:"github"`
	ServiceNow *ServiceNow `yaml:"servicenow"`
	MSGraph    *MSGraph    `yaml:"msgraph"`
	Atlassian  *Atlassian  `yaml:"atlassian"`
}

// AWS is the web-identity provider section.
type AWS struct {
	AuthorizationServer string `yaml:"authorization_server"`
	Scope               string `yaml:"scope"`
	TokenFile           string `yaml:"token_file"`
	FileMode            string `yaml:"file_mode"`
	RoleARN             string `yaml:"role_arn"`
	RoleSessionName     string `yaml:"role_session_name"`
	Region              string `yaml:"region"`
}

// Store locates a persisted credential.
type Store struct {
	Type     string `yaml:"type"`
	SecretID string `yaml:"secret_id"`
}

// GitIdentity is the git user for configure git.
type GitIdentity struct {
	Name  string `yaml:"name"`
	Email string `yaml:"email"`
}

// GitHub is the GitHub provider section.
type GitHub struct {
	APIBase           string      `yaml:"api_base"`
	Mode              string      `yaml:"mode"`
	Login             string      `yaml:"login"`
	OAuthClientID     string      `yaml:"oauth_client_id"`
	Store             Store       `yaml:"store"`
	ExpiryWarningDays int         `yaml:"expiry_warning_days"`
	GitIdentity       GitIdentity `yaml:"git_identity"`
}

// ServiceNow is the ServiceNow provider section.
type ServiceNow struct {
	InstanceURL         string `yaml:"instance_url"`
	AuthorizationServer string `yaml:"authorization_server"`
	Scope               string `yaml:"scope"`
	MinTTLSeconds       int    `yaml:"min_ttl_seconds"`
}

// MSGraph is the Microsoft Graph provider section.
type MSGraph struct {
	TenantID          string   `yaml:"tenant_id"`
	AppClientID       string   `yaml:"app_client_id"`
	UPN               string   `yaml:"upn"`
	Scopes            []string `yaml:"scopes"`
	Store             Store    `yaml:"store"`
	ReauthWarningDays int      `yaml:"reauth_warning_days"`
}

// Sink is a file sink.
type Sink struct {
	File string `yaml:"file"`
	Mode string `yaml:"mode"`
}

// Atlassian is the generic secret provider section.
type Atlassian struct {
	Type     string `yaml:"type"`
	Source   string `yaml:"source"`
	SecretID string `yaml:"secret_id"`
	Sink     Sink   `yaml:"sink"`
}

// Refresh tunes the scheduler.
type Refresh struct {
	Fraction         float64 `yaml:"fraction"`
	Jitter           float64 `yaml:"jitter"`
	MinMarginSeconds int     `yaml:"min_margin_seconds"`
}

// IPC configures the unix socket API. AllowGIDs entries are group names or
// numeric gids.
type IPC struct {
	Socket    string   `yaml:"socket"`
	AllowGIDs []string `yaml:"allow_gids"`
}

// Log configures logging.
type Log struct {
	Level       string `yaml:"level"`
	Format      string `yaml:"format"`
	Destination string `yaml:"destination"`
}

// Load reads and parses the file at path. A missing or unreadable file is an
// ErrConfig.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-supplied config path
	if err != nil {
		return nil, errf("config file: cannot read (%s)", reason(err))
	}
	return Parse(b)
}

// Parse decodes YAML, rejects unknown fields, applies defaults and validates.
func Parse(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errf("config file: empty document")
		}
		// yaml errors can quote input values; report only the position.
		return nil, errf("config file: invalid YAML%s", yamlPos(err))
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func reason(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "not found"
	case errors.Is(err, os.ErrPermission):
		return "permission denied"
	default:
		return "read error"
	}
}

var lineRe = regexp.MustCompile(`line (\d+)`)

func yamlPos(err error) string {
	if m := lineRe.FindStringSubmatch(err.Error()); m != nil {
		return " near line " + m[1]
	}
	return ""
}

func errf(format string, a ...any) error {
	return fmt.Errorf("%w: %s", domain.ErrConfig, fmt.Sprintf(format, a...))
}

// Default values.
const (
	DefaultAlg               = "RS256"
	DefaultFileMode          = "0440"
	DefaultGitHubAPIBase     = "https://api.github.com"
	DefaultExpiryWarnDays    = 30
	DefaultReauthWarnDays    = 14
	DefaultMinTTLSeconds     = 120
	DefaultRefreshFraction   = 0.5
	DefaultRefreshJitter     = 0.05
	DefaultMinMarginSeconds  = 120
	DefaultLogLevel          = "info"
	DefaultLogFormat         = "json"
	DefaultLogDestination    = "stderr"
	defaultSocketFile        = "agentd.sock"
	defaultRuntimeDirLinux   = "/run/agentd/"
	defaultRuntimeDirDarwin  = "/var/run/agentd/"
	defaultSecretSinkMode    = "0440"
	defaultAtlassianSinkName = "atlassian.key"
)

func runtimeDir(id string) string {
	if runtime.GOOS == "darwin" {
		return defaultRuntimeDirDarwin + id + "/"
	}
	return defaultRuntimeDirLinux + id + "/"
}

func (c *Config) applyDefaults() {
	if c.Okta.Signer.Alg == "" {
		c.Okta.Signer.Alg = DefaultAlg
	}
	if c.Refresh.Fraction == 0 {
		c.Refresh.Fraction = DefaultRefreshFraction
	}
	if c.Refresh.Jitter == 0 {
		c.Refresh.Jitter = DefaultRefreshJitter
	}
	if c.Refresh.MinMarginSeconds == 0 {
		c.Refresh.MinMarginSeconds = DefaultMinMarginSeconds
	}
	if c.Log.Level == "" {
		c.Log.Level = DefaultLogLevel
	}
	if c.Log.Format == "" {
		c.Log.Format = DefaultLogFormat
	}
	if c.Log.Destination == "" {
		c.Log.Destination = DefaultLogDestination
	}
	if c.IPC.Socket == "" && c.Agent.ID != "" {
		c.IPC.Socket = runtimeDir(c.Agent.ID) + defaultSocketFile
	}
	if a := c.Providers.AWS; a != nil {
		if a.FileMode == "" {
			a.FileMode = DefaultFileMode
		}
		if a.RoleSessionName == "" {
			a.RoleSessionName = c.Agent.ID // AWS-3: CloudTrail attributes by agent id
		}
		if a.TokenFile == "" && c.Agent.ID != "" {
			a.TokenFile = runtimeDir(c.Agent.ID) + "aws-web-identity.jwt"
		}
	}
	if g := c.Providers.GitHub; g != nil {
		if g.APIBase == "" {
			g.APIBase = DefaultGitHubAPIBase
		}
		if g.ExpiryWarningDays == 0 {
			g.ExpiryWarningDays = DefaultExpiryWarnDays
		}
	}
	if s := c.Providers.ServiceNow; s != nil && s.MinTTLSeconds == 0 {
		s.MinTTLSeconds = DefaultMinTTLSeconds
	}
	if m := c.Providers.MSGraph; m != nil && m.ReauthWarningDays == 0 {
		m.ReauthWarningDays = DefaultReauthWarnDays
	}
	if a := c.Providers.Atlassian; a != nil {
		if a.Type == "" {
			a.Type = "secret"
		}
		if a.Sink.Mode == "" {
			a.Sink.Mode = defaultSecretSinkMode
		}
		if a.Sink.File == "" && c.Agent.ID != "" {
			a.Sink.File = runtimeDir(c.Agent.ID) + defaultAtlassianSinkName
		}
	}
}

// Warnings lists non-fatal notices (flagged assumptions) for doctor and logs.
func (c *Config) Warnings() []string {
	var w []string
	// ASSUMPTION(A-01): Okta accepting ES256 client assertions is unconfirmed.
	if c.Okta.Signer.Alg == "ES256" {
		w = append(w, "okta.signer.alg: ES256 is flagged (A-01), unconfirmed Okta support; RS256 is the default")
	}
	// ASSUMPTION(A-06): the GitHub CLI public OAuth app may not be allowed for EMU users.
	if g := c.Providers.GitHub; g != nil && g.Mode == "oauth_device" && g.OAuthClientID == "" {
		w = append(w, "providers.github.oauth_client_id: empty, the GitHub CLI public app default is flagged (A-06)")
	}
	return w
}

// parseMode validates an octal permission string such as "0440".
func parseMode(s string) (os.FileMode, bool) {
	if s == "" || len(s) > 4 {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil || n > 0o777 {
		return 0, false
	}
	return os.FileMode(n), true
}
