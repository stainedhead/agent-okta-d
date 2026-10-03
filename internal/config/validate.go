package config

import (
	"net/url"
	"strings"
)

// Validate checks required fields and enumerations. The first problem found is
// returned as an ErrConfig naming the field path; values are never echoed.
func (c *Config) Validate() error {
	checks := []func() error{
		c.validateAgent, c.validateOkta, c.validateProviders,
		c.validateRefresh, c.validateIPC, c.validateLog,
	}
	for _, f := range checks {
		if err := f(); err != nil {
			return err
		}
	}
	return nil
}

func required(path, v string) error {
	if strings.TrimSpace(v) == "" {
		return errf("%s: required", path)
	}
	return nil
}

func oneOf(path, v string, allowed ...string) error {
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return errf("%s: must be one of %s", path, strings.Join(allowed, " | "))
}

func httpsURL(path, v string) error {
	if err := required(path, v); err != nil {
		return err
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errf("%s: must be an https URL", path)
	}
	return nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

var idChars = func(r rune) bool {
	return r == '-' || r == '_' || r == '.' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

func (c *Config) validateAgent() error {
	if err := required("agent.id", c.Agent.ID); err != nil {
		return err
	}
	// The id appears in paths, session names and log fields.
	if strings.IndexFunc(c.Agent.ID, func(r rune) bool { return !idChars(r) }) >= 0 || strings.HasPrefix(c.Agent.ID, ".") {
		return errf("agent.id: only letters, digits, '-', '_', '.' allowed")
	}
	return nil
}

func (c *Config) validateOkta() error {
	s := c.Okta.Signer
	if err := firstErr(
		httpsURL("okta.org_url", c.Okta.OrgURL),
		required("okta.client_id", c.Okta.ClientID),
		oneOf("okta.signer.type", s.Type, "kms", "keychain", "tpm", "file"),
		oneOf("okta.signer.alg", s.Alg, "RS256", "ES256"),
		required("okta.signer.kid", s.KID),
	); err != nil {
		return err
	}
	if s.Type == "kms" || s.Type == "file" {
		return required("okta.signer.key_id", s.KeyID)
	}
	return nil
}

func (c *Config) validateProviders() error {
	p := c.Providers
	if p.AWS != nil {
		if err := p.AWS.validate(); err != nil {
			return err
		}
	}
	if p.GitHub != nil {
		if err := p.GitHub.validate(); err != nil {
			return err
		}
	}
	if p.ServiceNow != nil {
		if err := p.ServiceNow.validate(); err != nil {
			return err
		}
	}
	if p.MSGraph != nil {
		if err := p.MSGraph.validate(); err != nil {
			return err
		}
	}
	if p.Atlassian != nil {
		return p.Atlassian.validate()
	}
	return nil
}

func (a *AWS) validate() error {
	if _, ok := parseMode(a.FileMode); !ok {
		return errf("providers.aws.file_mode: must be an octal mode such as \"0440\"")
	}
	return firstErr(
		required("providers.aws.authorization_server", a.AuthorizationServer),
		required("providers.aws.scope", a.Scope),
		required("providers.aws.token_file", a.TokenFile),
		required("providers.aws.role_arn", a.RoleARN),
		required("providers.aws.region", a.Region),
	)
}

func (s Store) validate(path string) error {
	return firstErr(
		oneOf(path+".type", s.Type, "aws-secretsmanager", "keychain", "file-encrypted"),
		required(path+".secret_id", s.SecretID),
	)
}

func (g *GitHub) validate() error {
	if err := firstErr(
		httpsURL("providers.github.api_base", g.APIBase),
		oneOf("providers.github.mode", g.Mode, "pat", "oauth_device"),
		required("providers.github.login", g.Login),
		g.Store.validate("providers.github.store"),
	); err != nil {
		return err
	}
	if g.ExpiryWarningDays < 0 {
		return errf("providers.github.expiry_warning_days: must not be negative")
	}
	return nil
}

func (s *ServiceNow) validate() error {
	if err := firstErr(
		httpsURL("providers.servicenow.instance_url", s.InstanceURL),
		required("providers.servicenow.authorization_server", s.AuthorizationServer),
		required("providers.servicenow.scope", s.Scope),
	); err != nil {
		return err
	}
	if s.MinTTLSeconds < 0 {
		return errf("providers.servicenow.min_ttl_seconds: must not be negative")
	}
	return nil
}

func (m *MSGraph) validate() error {
	if err := firstErr(
		required("providers.msgraph.tenant_id", m.TenantID),
		required("providers.msgraph.app_client_id", m.AppClientID),
		required("providers.msgraph.upn", m.UPN),
	); err != nil {
		return err
	}
	if len(m.Scopes) == 0 {
		return errf("providers.msgraph.scopes: required")
	}
	if err := m.Store.validate("providers.msgraph.store"); err != nil {
		return err
	}
	if m.ReauthWarningDays < 0 {
		return errf("providers.msgraph.reauth_warning_days: must not be negative")
	}
	return nil
}

func (a *Atlassian) validate() error {
	if err := firstErr(
		oneOf("providers.atlassian.type", a.Type, "secret"),
		oneOf("providers.atlassian.source", a.Source, "aws-secretsmanager"),
		required("providers.atlassian.secret_id", a.SecretID),
		required("providers.atlassian.sink.file", a.Sink.File),
	); err != nil {
		return err
	}
	if _, ok := parseMode(a.Sink.Mode); !ok {
		return errf("providers.atlassian.sink.mode: must be an octal mode such as \"0440\"")
	}
	return nil
}

func (c *Config) validateRefresh() error {
	r := c.Refresh
	if r.Fraction <= 0 || r.Fraction >= 1 {
		return errf("refresh.fraction: must be > 0 and < 1")
	}
	if r.Jitter < 0 || r.Jitter >= 1 {
		return errf("refresh.jitter: must be >= 0 and < 1")
	}
	if r.MinMarginSeconds < 0 {
		return errf("refresh.min_margin_seconds: must not be negative")
	}
	return nil
}

func (c *Config) validateIPC() error {
	if err := required("ipc.socket", c.IPC.Socket); err != nil {
		return err
	}
	if len(c.IPC.AllowGIDs) == 0 {
		return errf("ipc.allow_gids: at least one gid or group required (fail closed)")
	}
	for i := range c.IPC.AllowGIDs {
		if strings.TrimSpace(c.IPC.AllowGIDs[i]) == "" {
			return errf("ipc.allow_gids[%d]: must not be empty", i)
		}
	}
	return nil
}

func (c *Config) validateLog() error {
	return firstErr(
		oneOf("log.level", c.Log.Level, "debug", "info", "warn", "error"),
		oneOf("log.format", c.Log.Format, "json"),
		required("log.destination", c.Log.Destination),
	)
}
