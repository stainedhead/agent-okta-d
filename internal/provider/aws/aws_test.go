package aws_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/domain/domaintest"
	"github.com/stainedhead/agent-okta-d/internal/provider/aws"
)

func cfg() aws.Config {
	return aws.Config{
		AgentID: "sdlc-reviewer-01", AuthServer: "agents-aws", Scope: "aws.assume",
		TokenFile: "/run/agentd/sdlc-reviewer-01/aws-web-identity.jwt",
		RoleARN:   "arn:aws:iam::222222222222:role/agent-sdlc-reviewer-01", Region: "us-east-1",
		Owner: "agentd", Group: "agent",
	}
}

type fakeSTS struct {
	id    aws.Identity
	err   error
	calls int
	token string
}

func (f *fakeSTS) GetCallerIdentity(_ context.Context, _, _ string, t domain.SecretString) (aws.Identity, error) {
	f.calls++
	f.token = t.Reveal()
	return f.id, f.err
}

func okSTS() *fakeSTS {
	return &fakeSTS{id: aws.Identity{Account: "222222222222", ARN: "arn:aws:sts::222222222222:assumed-role/agent-sdlc-reviewer-01/sdlc-reviewer-01"}}
}

func TestConfigValidate(t *testing.T) {
	if err := cfg().Validate(); err != nil {
		t.Fatal(err)
	}
	mut := map[string]func(*aws.Config){
		"agent id": func(c *aws.Config) { c.AgentID = "a b" },
		"empty id": func(c *aws.Config) { c.AgentID = "" },
		"auth":     func(c *aws.Config) { c.AuthServer = "" },
		"scope":    func(c *aws.Config) { c.Scope = "" },
		"rel path": func(c *aws.Config) { c.TokenFile = "tok.jwt" },
		"newline":  func(c *aws.Config) { c.TokenFile = "/a\nb" },
		"role":     func(c *aws.Config) { c.RoleARN = "arn:aws:iam::1:user/x" },
		"region":   func(c *aws.Config) { c.Region = "us east" },
	}
	for name, f := range mut {
		c := cfg()
		f(&c)
		if err := c.Validate(); !errors.Is(err, domain.ErrConfig) {
			t.Errorf("%s: got %v want ErrConfig", name, err)
		}
		if _, err := aws.New(c, nil); !errors.Is(err, domain.ErrConfig) {
			t.Errorf("%s: New: %v", name, err)
		}
	}
	c := cfg()
	c.Region = ""
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestNameAndSinks(t *testing.T) {
	p, _ := aws.New(cfg(), nil)
	if p.Name() != "aws" {
		t.Fatal(p.Name())
	}
	s := p.Sinks()
	if len(s) != 1 || s[0].Mode != 0o440 || s[0].Owner != "agentd" || s[0].Group != "agent" ||
		s[0].Path != cfg().TokenFile || s[0].Format != domain.SinkRaw {
		t.Fatalf("%+v", s)
	}
}

func TestMint(t *testing.T) {
	p, _ := aws.New(cfg(), nil)
	d := domaintest.NewFakeDeps()
	c, err := p.Mint(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != domain.KindAWSWebIdentity || c.TTL() != time.Hour || c.Value.Reveal() != "okta-fake-token" {
		t.Fatalf("%+v", c)
	}
	req := d.OktaV.(*domaintest.FakeOkta).Requests[0]
	if req.AuthServer != "agents-aws" || req.Scope != "aws.assume" {
		t.Fatalf("%+v", req)
	}
	if c.Meta[domain.MetaJTI] != "jti-fake" || c.Meta[domain.MetaScope] != "aws.assume" {
		t.Fatalf("%v", c.Meta)
	}
}

// TTL is taken from the response, never hardcoded.
func TestMintTTLFromResponse_A02(t *testing.T) {
	p, _ := aws.New(cfg(), nil)
	d := domaintest.NewFakeDeps()
	d.OktaV = &domaintest.FakeOkta{TokenFn: func(context.Context, domain.OktaTokenRequest) (domain.OktaToken, error) {
		return domain.OktaToken{AccessToken: domain.NewSecret("t"), IssuedAt: domaintest.Epoch, ExpiresAt: domaintest.Epoch.Add(17 * time.Minute)}, nil
	}}
	c, err := p.Mint(context.Background(), d)
	if err != nil || c.TTL() != 17*time.Minute {
		t.Fatalf("%v %v", c.TTL(), err)
	}
	if c.Audience() != aws.DefaultAudience {
		t.Fatalf("aud %q", c.Audience())
	}
}

func TestMintIssuedAtDefaultsToClock(t *testing.T) {
	p, _ := aws.New(cfg(), nil)
	d := domaintest.NewFakeDeps()
	d.OktaV = &domaintest.FakeOkta{TokenFn: func(context.Context, domain.OktaTokenRequest) (domain.OktaToken, error) {
		return domain.OktaToken{AccessToken: domain.NewSecret("t"), ExpiresAt: domaintest.Epoch.Add(time.Hour)}, nil
	}}
	c, err := p.Mint(context.Background(), d)
	if err != nil || !c.IssuedAt.Equal(domaintest.Epoch) {
		t.Fatalf("%v %v", c.IssuedAt, err)
	}
}

func TestMintErrors(t *testing.T) {
	p, _ := aws.New(cfg(), nil)
	d := domaintest.NewFakeDeps()
	boom := domain.NewTransient(errors.New("okta down"), 0)
	d.OktaV = &domaintest.FakeOkta{TokenFn: func(context.Context, domain.OktaTokenRequest) (domain.OktaToken, error) {
		return domain.OktaToken{}, boom
	}}
	if _, err := p.Mint(context.Background(), d); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("%v", err)
	}
	for name, tok := range map[string]domain.OktaToken{
		"empty":     {ExpiresAt: domaintest.Epoch.Add(time.Hour)},
		"no expiry": {AccessToken: domain.NewSecret("t")},
		"expired":   {AccessToken: domain.NewSecret("t"), IssuedAt: domaintest.Epoch, ExpiresAt: domaintest.Epoch.Add(-time.Minute)},
	} {
		d.OktaV = &domaintest.FakeOkta{TokenFn: func(context.Context, domain.OktaTokenRequest) (domain.OktaToken, error) { return tok, nil }}
		if _, err := p.Mint(context.Background(), d); !errors.Is(err, domain.ErrProvider) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestMintErrorNeverLeaksToken(t *testing.T) {
	p, _ := aws.New(cfg(), nil)
	d := domaintest.NewFakeDeps()
	d.OktaV = &domaintest.FakeOkta{TokenFn: func(context.Context, domain.OktaTokenRequest) (domain.OktaToken, error) {
		return domain.OktaToken{AccessToken: domain.NewSecret("SECRET-TOKEN")}, nil
	}}
	_, err := p.Mint(context.Background(), d)
	if err == nil || strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Fatalf("%v", err)
	}
}

func TestNextRefreshIs50Percent(t *testing.T) {
	c := domain.Credential{IssuedAt: domaintest.Epoch, ExpiresAt: domaintest.Epoch.Add(time.Hour)}
	if got := aws.NextRefresh(c); !got.Equal(domaintest.Epoch.Add(30 * time.Minute)) {
		t.Fatal(got)
	}
}

func TestRevokeDeletesTokenFile(t *testing.T) {
	sink := &domaintest.FakeSink{}
	p, _ := aws.New(cfg(), nil, aws.WithSink(sink))
	_ = sink.Write(context.Background(), p.Sinks()[0], domain.NewSecret("x"))
	if err := p.Revoke(context.Background(), domain.Credential{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := sink.Content(cfg().TokenFile); ok {
		t.Fatal("token file still present")
	}
	// no sink: no-op
	p2, _ := aws.New(cfg(), nil)
	if err := p2.Revoke(context.Background(), domain.Credential{}); err != nil {
		t.Fatal(err)
	}
}

type errSink struct{ domaintest.FakeSink }

func (*errSink) Remove(context.Context, domain.SinkSpec) error { return errors.New("rm failed") }

func TestRevokeSinkError(t *testing.T) {
	p, _ := aws.New(cfg(), nil, aws.WithSink(&errSink{}))
	if err := p.Revoke(context.Background(), domain.Credential{}); err == nil {
		t.Fatal("want error")
	}
}

func TestProbe(t *testing.T) {
	sts := okSTS()
	p, _ := aws.New(cfg(), sts)
	c := domain.Credential{Value: domain.NewSecret("jwt")}
	if err := p.Probe(context.Background(), c); err != nil || sts.calls != 1 || sts.token != "jwt" {
		t.Fatalf("%v %+v", err, sts)
	}
}

func TestProbeFailures(t *testing.T) {
	c := domain.Credential{Value: domain.NewSecret("jwt")}
	ctx := context.Background()

	p, _ := aws.New(cfg(), nil)
	if err := p.Probe(ctx, c); !errors.Is(err, domain.ErrConfig) {
		t.Errorf("nil sts: %v", err)
	}
	for name, tc := range map[string]struct {
		sts  *fakeSTS
		want error
	}{
		"transient":  {&fakeSTS{err: domain.NewTransient(errors.New("throttle"), 0)}, domain.ErrTransient},
		"denied":     {&fakeSTS{err: domain.Wrap(domain.ErrAuthDefinitive, errors.New("AccessDenied"))}, domain.ErrAuthDefinitive},
		"unknown":    {&fakeSTS{err: errors.New("weird")}, domain.ErrProvider},
		"wrong role": {&fakeSTS{id: aws.Identity{ARN: "arn:aws:sts::222222222222:assumed-role/other/sdlc-reviewer-01"}}, domain.ErrProvider},
		"wrong sess": {&fakeSTS{id: aws.Identity{ARN: "arn:aws:sts::222222222222:assumed-role/agent-sdlc-reviewer-01/someone"}}, domain.ErrProvider},
	} {
		p, _ := aws.New(cfg(), tc.sts)
		if err := p.Probe(ctx, c); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSnippets(t *testing.T) {
	got, err := aws.ProfileSnippet(cfg())
	if err != nil {
		t.Fatal(err)
	}
	want := "[profile agent]\nrole_arn = arn:aws:iam::222222222222:role/agent-sdlc-reviewer-01\n" +
		"web_identity_token_file = /run/agentd/sdlc-reviewer-01/aws-web-identity.jwt\n" +
		"role_session_name = sdlc-reviewer-01\nregion = us-east-1\n"
	if got != want {
		t.Fatalf("got:\n%s", got)
	}
	env, err := aws.EnvSnippet(cfg())
	if err != nil || !strings.Contains(env, "export AWS_ROLE_SESSION_NAME=sdlc-reviewer-01\n") ||
		!strings.Contains(env, "export AWS_WEB_IDENTITY_TOKEN_FILE=/run/agentd/sdlc-reviewer-01/aws-web-identity.jwt\n") ||
		!strings.Contains(env, "export AWS_REGION=us-east-1\n") {
		t.Fatalf("%v\n%s", err, env)
	}
	c := cfg()
	c.Region = ""
	p, _ := aws.ProfileSnippet(c)
	e, _ := aws.EnvSnippet(c)
	if strings.Contains(p, "region") || strings.Contains(e, "REGION") {
		t.Fatal("region should be omitted")
	}
	c.RoleARN = "bad"
	if _, err := aws.ProfileSnippet(c); !errors.Is(err, domain.ErrConfig) {
		t.Fatal(err)
	}
	if _, err := aws.EnvSnippet(c); !errors.Is(err, domain.ErrConfig) {
		t.Fatal(err)
	}
}

// Simulated 24 h rotation (M1): refresh at 50 % of each token's TTL; the token
// file must hold an unexpired token at every minute, with no mint errors.
func TestSimulated24hRotation(t *testing.T) {
	ctx := context.Background()
	d := domaintest.NewFakeDeps()
	clk := d.ClockV.(*domaintest.FakeClock)
	n := 0
	d.OktaV = &domaintest.FakeOkta{TokenFn: func(context.Context, domain.OktaTokenRequest) (domain.OktaToken, error) {
		n++
		now := clk.Now()
		return domain.OktaToken{
			AccessToken: domain.NewSecret("tok-" + time.Duration(n).String()),
			IssuedAt:    now, ExpiresAt: now.Add(time.Hour), JTI: "j",
		}, nil
	}}
	sink := &domaintest.FakeSink{}
	sts := okSTS()
	p, _ := aws.New(cfg(), sts, aws.WithSink(sink))
	spec := p.Sinks()[0]

	cred, err := p.Mint(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	_ = sink.Write(ctx, spec, cred.Value)
	next := aws.NextRefresh(cred)
	start := clk.Now()
	rotations := 0
	for clk.Now().Sub(start) < 24*time.Hour {
		clk.Advance(time.Minute)
		if !clk.Now().Before(next) {
			if cred, err = p.Mint(ctx, d); err != nil {
				t.Fatalf("mint at %v: %v", clk.Now().Sub(start), err)
			}
			if err = p.Probe(ctx, cred); err != nil {
				t.Fatal(err)
			}
			_ = sink.Write(ctx, spec, cred.Value)
			next = aws.NextRefresh(cred)
			rotations++
		}
		if cred.Expired(clk.Now()) {
			t.Fatalf("token file expired at %v", clk.Now().Sub(start))
		}
		if got, _ := sink.Content(spec.Path); got != cred.Value.Reveal() {
			t.Fatalf("file out of sync at %v", clk.Now().Sub(start))
		}
	}
	if rotations != 48 {
		t.Fatalf("rotations=%d want 48 (every 30 min for 24 h)", rotations)
	}
	if err := p.Revoke(ctx, cred); err != nil {
		t.Fatal(err)
	}
	if _, ok := sink.Content(spec.Path); ok {
		t.Fatal("file not deleted on revoke")
	}
}
