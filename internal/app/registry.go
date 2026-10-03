package app

import (
	"io/fs"
	"runtime"
	"strconv"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/cache"
	"github.com/stainedhead/agent-okta-d/internal/config"
	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/okta"
	awsprov "github.com/stainedhead/agent-okta-d/internal/provider/aws"
	ghprov "github.com/stainedhead/agent-okta-d/internal/provider/github"
	"github.com/stainedhead/agent-okta-d/internal/provider/msgraph"
	"github.com/stainedhead/agent-okta-d/internal/provider/secret"
	"github.com/stainedhead/agent-okta-d/internal/provider/servicenow"
)

// Provider type names registered by DefaultRegistry.
const (
	TypeAWS        = "aws"
	TypeGitHub     = "github"
	TypeServiceNow = "servicenow"
	TypeMSGraph    = "msgraph"
	TypeSecret     = "secret" // providers.atlassian
)

// Registered is a built provider with its cache options and, for Okta-backed
// providers, the authorization server it needs.
type Registered struct {
	Provider domain.Provider
	Key      domain.Key
	Options  cache.Options
	// OktaServers lists the Okta authorization servers the provider mints
	// from (config name -> id and audience).
	OktaServers map[string]okta.AuthServer
}

// Factory builds the provider of one type from the config. It returns nil
// without error when the type is not configured.
type Factory func(cfg *config.Config, env Env) (*Registered, error)

// Registry maps provider types to factories, in registration order.
type Registry struct {
	order []string
	m     map[string]Factory
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{m: map[string]Factory{}} }

// Register adds a factory; registering a type twice replaces it.
func (r *Registry) Register(typ string, f Factory) {
	if _, ok := r.m[typ]; !ok {
		r.order = append(r.order, typ)
	}
	r.m[typ] = f
}

// Types lists the registered provider types in registration order.
func (r *Registry) Types() []string { return append([]string(nil), r.order...) }

// Build constructs every configured provider. The first error aborts.
func (r *Registry) Build(cfg *config.Config, env Env) ([]*Registered, error) {
	var out []*Registered
	for _, typ := range r.order {
		reg, err := r.m[typ](cfg, env)
		if err != nil {
			return nil, err
		}
		if reg != nil {
			out = append(out, reg)
		}
	}
	return out, nil
}

// DefaultRegistry registers aws, github, servicenow, msgraph and secret.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(TypeAWS, buildAWS)
	r.Register(TypeGitHub, buildGitHub)
	r.Register(TypeServiceNow, buildServiceNow)
	r.Register(TypeMSGraph, buildMSGraph)
	r.Register(TypeSecret, buildSecret)
	return r
}

// stateDir is where persistent daemon state lives (file-encrypted store).
func stateDir(agentID string) string {
	if runtime.GOOS == "darwin" {
		return "/var/db/agentd/" + agentID
	}
	return "/var/lib/agentd/" + agentID
}

// sinkGroup is the group that gets read access to credential files: the first
// ipc.allow_gids entry that is a group name.
func sinkGroup(cfg *config.Config) string {
	for _, g := range cfg.IPC.AllowGIDs {
		if _, err := strconv.Atoi(g); err != nil {
			return g
		}
	}
	return ""
}

// authServer resolves a provider's authorization server name to its Okta id
// and audience; a name without an okta.authorization_servers entry is its own
// id.
func authServer(cfg *config.Config, name, defaultAudience string) map[string]okta.AuthServer {
	as := okta.AuthServer{ID: name, Audience: defaultAudience}
	if c, ok := cfg.Okta.AuthorizationServers[name]; ok {
		if c.ID != "" {
			as.ID = c.ID
		}
		if c.Audience != "" {
			as.Audience = c.Audience
		}
	}
	return map[string]okta.AuthServer{name: as}
}

// AWSConfig converts the config section for the aws provider.
func AWSConfig(cfg *config.Config) awsprov.Config {
	a := cfg.Providers.AWS
	if a == nil {
		return awsprov.Config{}
	}
	return awsprov.Config{
		AgentID: cfg.Agent.ID, AuthServer: a.AuthorizationServer, Scope: a.Scope, TokenFile: a.TokenFile,
		RoleARN: a.RoleARN, Region: a.Region, Group: sinkGroup(cfg),
	}
}

func buildAWS(cfg *config.Config, env Env) (*Registered, error) {
	a := cfg.Providers.AWS
	if a == nil {
		return nil, nil //nolint:nilnil // not configured
	}
	ac := AWSConfig(cfg)
	var opts []awsprov.Option
	if env.Sink != nil {
		opts = append(opts, awsprov.WithSink(env.Sink))
	}
	p, err := awsprov.New(ac, env.STS, opts...)
	if err != nil {
		return nil, err
	}
	return &Registered{
		Provider: p,
		Key:      domain.Key{Provider: awsprov.Name, Audience: awsprov.DefaultAudience, Scope: a.Scope},
		// AWS-2: refresh at or before 50 %: 0.45 plus at most 0.05 jitter.
		Options:     cache.Options{Fraction: 0.45, Jitter: min(cfg.Refresh.Jitter, 0.05)},
		OktaServers: authServer(cfg, a.AuthorizationServer, awsprov.DefaultAudience),
	}, nil
}

func buildGitHub(cfg *config.Config, env Env) (*Registered, error) {
	g := cfg.Providers.GitHub
	if g == nil {
		return nil, nil //nolint:nilnil // not configured
	}
	p, err := ghprov.New(GitHubConfig(cfg, env))
	if err != nil {
		return nil, err
	}
	return &Registered{Provider: p, Key: domain.Key{Provider: ghprov.ProviderName}}, nil
}

// GitHubConfig converts the config section for the github provider.
func GitHubConfig(cfg *config.Config, env Env) ghprov.Config {
	g := cfg.Providers.GitHub
	if g == nil {
		return ghprov.Config{}
	}
	return ghprov.Config{
		APIBase: g.APIBase, Mode: ghprov.Mode(g.Mode), Login: g.Login, OAuthClientID: g.OAuthClientID,
		StoreName: g.Store.Type, SecretID: g.Store.SecretID, ExpiryWarningDays: g.ExpiryWarningDays,
		GitName: g.GitIdentity.Name, GitEmail: g.GitIdentity.Email, ProbeRepo: g.ProbeRepo, HTTPClient: env.HTTP,
	}
}

func buildServiceNow(cfg *config.Config, env Env) (*Registered, error) {
	s := cfg.Providers.ServiceNow
	if s == nil {
		return nil, nil //nolint:nilnil // not configured
	}
	p, err := servicenow.New(servicenow.Config{
		InstanceURL: s.InstanceURL, AuthServer: s.AuthorizationServer, Scope: s.Scope,
		MinTTL: time.Duration(s.MinTTLSeconds) * time.Second, HTTPClient: env.HTTP,
	})
	if err != nil {
		return nil, err
	}
	return &Registered{
		Provider: p,
		Key:      domain.Key{Provider: servicenow.ProviderName, Audience: s.InstanceURL, Scope: s.Scope},
		// SN-3: refresh synchronously when less than min_ttl remains.
		Options:     cache.Options{MinTTL: p.MinTTL()},
		OktaServers: authServer(cfg, s.AuthorizationServer, s.InstanceURL),
	}, nil
}

func buildMSGraph(cfg *config.Config, env Env) (*Registered, error) {
	m := cfg.Providers.MSGraph
	if m == nil {
		return nil, nil //nolint:nilnil // not configured
	}
	p, err := msgraph.New(msgraph.Config{
		TenantID: m.TenantID, ClientID: m.AppClientID, UPN: m.UPN, Scopes: m.Scopes,
		StoreName: m.Store.Type, SecretID: m.Store.SecretID, ProbeOtherUser: m.ProbeOtherUser, HTTP: env.HTTP,
	})
	if err != nil {
		return nil, err
	}
	return &Registered{Provider: p, Key: domain.Key{Provider: msgraph.ProviderName}}, nil
}

// DefaultSecretInterval is the atlassian re-fetch interval when none is set.
const DefaultSecretInterval = 15 * time.Minute

func buildSecret(cfg *config.Config, _ Env) (*Registered, error) {
	a := cfg.Providers.Atlassian
	if a == nil {
		return nil, nil //nolint:nilnil // not configured
	}
	mode, ok := parseMode(a.Sink.Mode)
	if !ok {
		return nil, domain.NewConfigError("providers.atlassian.sink.mode", "must be an octal mode such as \"0440\"")
	}
	iv := DefaultSecretInterval
	if a.IntervalSeconds > 0 {
		iv = time.Duration(a.IntervalSeconds) * time.Second
	}
	p, err := secret.New(secret.Config{
		Name: "atlassian", Source: a.Source, SecretID: a.SecretID, Interval: iv,
		SinkPath: a.Sink.File, Mode: mode, Group: sinkGroup(cfg),
	})
	if err != nil {
		return nil, err
	}
	return &Registered{Provider: p, Key: domain.Key{Provider: p.Name()}}, nil
}

func parseMode(s string) (m fs.FileMode, ok bool) {
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil || n > 0o777 || s == "" {
		return 0, false
	}
	return fs.FileMode(n), true
}

// SinkSpecs lists every sink of the providers.
func SinkSpecs(regs []*Registered) []domain.SinkSpec {
	var out []domain.SinkSpec
	for _, r := range regs {
		out = append(out, r.Provider.Sinks()...)
	}
	return out
}
