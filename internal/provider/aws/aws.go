// Package aws is the AWS provider (PRD 7.1, AWS-1..5). It mints an Okta access
// token from the agents-aws authorization server and exposes it as the
// web-identity token file that the stock AWS CLI/SDKs exchange with STS
// themselves. The daemon never talks to STS except through the injected
// STSClient used by doctor.
package aws

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// Name is the provider id used in config, URLs and audit events.
const Name = "aws"

// DefaultAudience is the audience Okta must stamp on agents-aws tokens.
const DefaultAudience = "sts.amazonaws.com"

// RefreshFraction is the share of the token TTL after which the cache must
// refresh (AWS-2: at most 50 %).
const RefreshFraction = 0.5

// TokenFileMode is the mandated token file mode (AWS-1).
const TokenFileMode fs.FileMode = 0o440

// Config is the aws provider configuration (PRD section 15, providers.aws).
type Config struct {
	AgentID    string // also the role session name (AWS-3)
	AuthServer string // Okta authorization server config name, e.g. "agents-aws"
	Scope      string // e.g. "aws.assume"
	TokenFile  string // absolute path
	RoleARN    string
	Region     string
	Owner      string // token file owner, e.g. "agentd"
	Group      string // token file group, e.g. "agent"
}

var (
	roleARNRe = regexp.MustCompile(`^arn:aws[a-z-]*:iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]+$`)
	safeRe    = regexp.MustCompile(`^[A-Za-z0-9._@:/+=,-]+$`)
)

// Validate checks the configuration and returns an ErrConfig-class error.
func (c Config) Validate() error {
	switch {
	case !safeRe.MatchString(c.AgentID):
		return domain.NewConfigError("providers.aws.agent_id", "required; letters, digits and ._@:/+=,- only")
	case c.AuthServer == "":
		return domain.NewConfigError("providers.aws.authorization_server", "required")
	case c.Scope == "":
		return domain.NewConfigError("providers.aws.scope", "required")
	case !strings.HasPrefix(c.TokenFile, "/") || strings.ContainsAny(c.TokenFile, "\r\n"):
		return domain.NewConfigError("providers.aws.token_file", "must be an absolute path without newlines")
	case !roleARNRe.MatchString(c.RoleARN):
		return domain.NewConfigError("providers.aws.role_arn", "must be an IAM role ARN")
	case c.Region != "" && !safeRe.MatchString(c.Region):
		return domain.NewConfigError("providers.aws.region", "invalid characters")
	}
	return nil
}

// Identity is the result of sts:GetCallerIdentity.
type Identity struct {
	Account string
	ARN     string // arn:aws:sts::<acct>:assumed-role/<role>/<session>
	UserID  string
}

// STSClient is the doctor probe seam (AWS-4). A real implementation performs
// AssumeRoleWithWebIdentity with the token and then GetCallerIdentity; tests
// use a fake. Implementations must classify failures: throttling/network as
// domain.ErrTransient, rejection as domain.ErrAuthDefinitive.
type STSClient interface {
	GetCallerIdentity(ctx context.Context, roleARN, sessionName string, token domain.SecretString) (Identity, error)
}

// Provider implements domain.Provider for AWS.
type Provider struct {
	cfg  Config
	sts  STSClient
	sink domain.Sink // optional; when set, Revoke deletes the token file
}

// Option customises New.
type Option func(*Provider)

// WithSink lets Revoke delete the token file itself (AWS-5).
func WithSink(s domain.Sink) Option { return func(p *Provider) { p.sink = s } }

// New validates cfg and builds the provider. sts may be nil, in which case
// Probe returns a config error.
func New(cfg Config, sts STSClient, opts ...Option) (*Provider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	p := &Provider{cfg: cfg, sts: sts}
	for _, o := range opts {
		o(p)
	}
	return p, nil
}

var _ domain.Provider = (*Provider)(nil)

// Name implements domain.Provider.
func (*Provider) Name() string { return Name }

// Sinks implements domain.Provider: the single token file, raw, mode 0440
// (AWS-1). The sink implementation writes atomically via temp file + rename.
func (p *Provider) Sinks() []domain.SinkSpec {
	return []domain.SinkSpec{{
		Path: p.cfg.TokenFile, Mode: TokenFileMode, Owner: p.cfg.Owner, Group: p.cfg.Group, Format: domain.SinkRaw,
	}}
}

// Mint implements domain.Provider (AWS-1). The lifetime comes from the Okta
// response (ASSUMPTION(A-02): never hardcoded).
func (p *Provider) Mint(ctx context.Context, d domain.Deps) (domain.Credential, error) {
	tok, err := d.Okta().Token(ctx, domain.OktaTokenRequest{AuthServer: p.cfg.AuthServer, Scope: p.cfg.Scope})
	if err != nil {
		return domain.Credential{}, err // already classified by the Okta source
	}
	if tok.AccessToken.IsZero() {
		return domain.Credential{}, domain.NewProviderError(Name, errors.New("okta returned an empty access token"))
	}
	if tok.IssuedAt.IsZero() {
		tok.IssuedAt = d.Clock().Now()
	}
	aud := tok.Audience
	if aud == "" {
		aud = DefaultAudience
	}
	c := domain.Credential{
		Kind: domain.KindAWSWebIdentity, Value: tok.AccessToken, IssuedAt: tok.IssuedAt, ExpiresAt: tok.ExpiresAt,
		Meta: map[string]string{domain.MetaAudience: aud, domain.MetaScope: tok.Scope, domain.MetaJTI: tok.JTI},
	}
	if err := c.Validate(); err != nil {
		return domain.Credential{}, domain.NewProviderError(Name, err)
	}
	return c, nil
}

// NextRefresh is when the cache must refresh c: IssuedAt + 50 % of the TTL
// (AWS-2).
func NextRefresh(c domain.Credential) time.Time {
	return c.IssuedAt.Add(time.Duration(float64(c.TTL()) * RefreshFraction))
}

// Revoke implements domain.Provider: delete the token file (AWS-5). Okta-side
// revocation is not attempted (ASSUMPTION(A-04): best effort only, owned by
// the Okta layer).
func (p *Provider) Revoke(ctx context.Context, _ domain.Credential) error {
	if p.sink == nil {
		return nil
	}
	for _, s := range p.Sinks() {
		if err := p.sink.Remove(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

// Probe implements domain.Provider (AWS-4): sts:GetCallerIdentity with the
// token must return an assumed-role identity whose session name is the agent
// id (what CloudTrail attributes).
func (p *Provider) Probe(ctx context.Context, c domain.Credential) error {
	if p.sts == nil {
		return domain.NewConfigError("providers.aws.sts", "no STS client configured")
	}
	id, err := p.sts.GetCallerIdentity(ctx, p.cfg.RoleARN, p.cfg.AgentID, c.Value)
	if err != nil {
		if errors.Is(err, domain.ErrTransient) || errors.Is(err, domain.ErrAuthDefinitive) {
			return err
		}
		return domain.NewProviderError(Name, err)
	}
	roleName := p.cfg.RoleARN[strings.LastIndex(p.cfg.RoleARN, "/")+1:]
	if !strings.Contains(id.ARN, ":assumed-role/"+roleName+"/"+p.cfg.AgentID) {
		return domain.NewProviderError(Name, fmt.Errorf("caller identity %q is not the expected role session", id.ARN))
	}
	return nil
}
