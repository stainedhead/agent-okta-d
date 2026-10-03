package secret_test

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/domain/domaintest"
	"github.com/stainedhead/agent-okta-d/internal/provider/secret"
)

const keyID = "arn:aws:secretsmanager:us-east-1:222222222222:secret:agents/a/atlassian"

func cfg() secret.Config {
	return secret.Config{
		Name: "atlassian", Source: "aws-secretsmanager", SecretID: keyID,
		Interval: 15 * time.Minute, SinkPath: "/run/agentd/a/atlassian.key",
	}
}

func setup(t *testing.T, value string) (*domaintest.FakeDeps, *domaintest.FakeStore) {
	t.Helper()
	d := domaintest.NewFakeDeps()
	st := &domaintest.FakeStore{}
	if value != "" {
		if _, err := st.Put(context.Background(), keyID, domain.NewSecret(value), ""); err != nil {
			t.Fatal(err)
		}
	}
	d.Stores["aws-secretsmanager"] = st
	return d, st
}

// AT-1: fetch from the store, hold in memory, ExpiresAt is the re-fetch horizon.
func TestAT1_MintFetchesAndSetsRefetchHorizon(t *testing.T) {
	d, _ := setup(t, "api-key-1")
	p, err := secret.New(cfg())
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "atlassian" {
		t.Fatalf("name %q", p.Name())
	}
	c, err := p.Mint(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	now := d.Clock().Now()
	if c.Kind != domain.KindStaticSecret || c.Value.Reveal() != "api-key-1" {
		t.Fatalf("bad credential %v", c.Kind)
	}
	if !c.IssuedAt.Equal(now) || c.TTL() != 15*time.Minute {
		t.Fatalf("issued=%v ttl=%v", c.IssuedAt, c.TTL())
	}
	if c.Meta[domain.MetaAudience] != "" || c.Meta[secret.MetaVersion] != "v1" {
		t.Fatalf("meta %v", c.Meta)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

// AT-1: re-fetch on interval picks up a rotated secret.
func TestAT1_RefetchPicksUpRotation(t *testing.T) {
	d, st := setup(t, "old")
	p, _ := secret.New(cfg())
	c1, _ := p.Mint(context.Background(), d)
	d.Clock().(*domaintest.FakeClock).Advance(15 * time.Minute)
	if _, err := st.Put(context.Background(), keyID, domain.NewSecret("new"), "v1"); err != nil {
		t.Fatal(err)
	}
	c2, err := p.Mint(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if c1.Value.Reveal() != "old" || c2.Value.Reveal() != "new" || !c2.IssuedAt.After(c1.IssuedAt) {
		t.Fatal("rotation not picked up")
	}
	if c2.Meta[secret.MetaVersion] != "v2" {
		t.Fatalf("version %v", c2.Meta)
	}
}

func TestMintErrors(t *testing.T) {
	ctx := context.Background()
	t.Run("missing secret is provider error", func(t *testing.T) {
		d, _ := setup(t, "")
		p, _ := secret.New(cfg())
		_, err := p.Mint(ctx, d)
		if !errors.Is(err, domain.ErrProvider) || !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("empty value is provider error", func(t *testing.T) {
		d, st := setup(t, "x")
		_, _ = st.Put(ctx, keyID, domain.NewSecret(""), "v1")
		p, _ := secret.New(cfg())
		if _, err := p.Mint(ctx, d); !errors.Is(err, domain.ErrProvider) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("unknown store is config error", func(t *testing.T) {
		d := domaintest.NewFakeDeps()
		p, _ := secret.New(cfg())
		if _, err := p.Mint(ctx, d); !errors.Is(err, domain.ErrConfig) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("classified store error passes through", func(t *testing.T) {
		d := domaintest.NewFakeDeps()
		d.Stores["aws-secretsmanager"] = errStore{domain.NewTransient(errors.New("503"), time.Second)}
		p, _ := secret.New(cfg())
		_, err := p.Mint(ctx, d)
		if !errors.Is(err, domain.ErrTransient) {
			t.Fatalf("got %v", err)
		}
		if _, ok := domain.RetryAfter(err); !ok {
			t.Fatal("retry hint lost")
		}
	})
	t.Run("unclassified store error is provider error", func(t *testing.T) {
		d := domaintest.NewFakeDeps()
		d.Stores["aws-secretsmanager"] = errStore{errors.New("boom")}
		p, _ := secret.New(cfg())
		if _, err := p.Mint(ctx, d); !errors.Is(err, domain.ErrProvider) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("context errors are transient", func(t *testing.T) {
		d := domaintest.NewFakeDeps()
		d.Stores["aws-secretsmanager"] = errStore{context.DeadlineExceeded}
		p, _ := secret.New(cfg())
		if _, err := p.Mint(ctx, d); !errors.Is(err, domain.ErrTransient) {
			t.Fatalf("got %v", err)
		}
	})
}

type errStore struct{ err error }

func (e errStore) Get(context.Context, string) (domain.SecretValue, error) {
	return domain.SecretValue{}, e.err
}
func (e errStore) Put(context.Context, string, domain.SecretString, string) (string, error) {
	return "", e.err
}

// AT-2(a)/AT-3: 0440 file sink spec, never world readable.
func TestAT2_SinkSpecDefaults(t *testing.T) {
	c := cfg()
	c.Owner, c.Group = "agentd", "agent"
	p, _ := secret.New(c)
	s := p.Sinks()
	if len(s) != 1 {
		t.Fatalf("sinks %v", s)
	}
	want := domain.SinkSpec{Path: c.SinkPath, Mode: fs.FileMode(0o440), Owner: "agentd", Group: "agent", Format: domain.SinkRaw}
	if s[0] != want {
		t.Fatalf("got %+v want %+v", s[0], want)
	}
}

func TestAT2_SinkFormatAndExplicitMode(t *testing.T) {
	c := cfg()
	c.Mode, c.Format = 0o400, domain.SinkRawNL
	p, err := secret.New(c)
	if err != nil {
		t.Fatal(err)
	}
	if s := p.Sinks()[0]; s.Mode != 0o400 || s.Format != domain.SinkRawNL {
		t.Fatalf("%+v", s)
	}
}

func TestAT2_NoSinkWhenPathEmpty(t *testing.T) {
	c := cfg()
	c.SinkPath = "" // served over the unix socket only (AT-2b)
	p, err := secret.New(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sinks()) != 0 {
		t.Fatal("expected no sinks")
	}
}

func TestAT3_RejectsWorldAccessibleModes(t *testing.T) {
	for _, m := range []fs.FileMode{0o444, 0o644, 0o640 | 0o002, 0o660, 0o441, 0o777} {
		c := cfg()
		c.Mode = m
		if _, err := secret.New(c); !errors.Is(err, domain.ErrPolicy) {
			t.Errorf("mode %o: got %v", m, err)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	cases := map[string]func(*secret.Config){
		"name":     func(c *secret.Config) { c.Name = "" },
		"source":   func(c *secret.Config) { c.Source = "" },
		"secretid": func(c *secret.Config) { c.SecretID = "" },
		"interval": func(c *secret.Config) { c.Interval = 0 },
		"negative": func(c *secret.Config) { c.Interval = -time.Second },
		"format":   func(c *secret.Config) { c.Format = "weird" },
		"relative": func(c *secret.Config) { c.SinkPath = "rel/path" },
	}
	for n, mut := range cases {
		c := cfg()
		mut(&c)
		if _, err := secret.New(c); !errors.Is(err, domain.ErrConfig) {
			t.Errorf("%s: got %v", n, err)
		}
	}
}

// AT-3 / FR-6: the value never reaches logs, errors or audit.
func TestValueNeverLeaks(t *testing.T) {
	var buf strings.Builder
	d, _ := setup(t, "TOPSECRET")
	d.LoggerV = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	p, _ := secret.New(cfg())
	c, err := p.Mint(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	_ = p.Probe(context.Background(), c)
	_ = p.Revoke(context.Background(), c)
	if strings.Contains(buf.String(), "TOPSECRET") {
		t.Fatal("secret in log")
	}
	for _, e := range d.AuditV.(*domaintest.RecordingAudit).Events() {
		if strings.Contains(e.Detail, "TOPSECRET") {
			t.Fatal("secret in audit")
		}
	}
}

func TestProbeAndRevoke(t *testing.T) {
	d, _ := setup(t, "k")
	p, _ := secret.New(cfg())
	c, _ := p.Mint(context.Background(), d)
	if err := p.Probe(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if err := p.Probe(context.Background(), domain.Credential{}); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("got %v", err)
	}
	d.Clock().(*domaintest.FakeClock).Advance(time.Hour)
	if err := p.Probe(context.Background(), c); err != nil {
		t.Fatalf("probe is shape-only: %v", err)
	}
	if err := p.Revoke(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

var _ domain.Provider = (*secret.Provider)(nil)
