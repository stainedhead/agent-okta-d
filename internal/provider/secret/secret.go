// Package secret implements the generic "secret" provider (PRD 7.4, AT-1..3):
// it fetches a static secret (for example the Atlassian service-account API
// key) from a configured SecretStore, holds it in memory only, and re-fetches
// it on an interval so rotation is picked up without a restart. The cache
// renders the credential into the 0440 file sink returned by Sinks.
package secret

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// MetaVersion is the Credential.Meta key holding the store's version token of
// the fetched secret (never the value).
const MetaVersion = "secret_version"

// DefaultMode is the sink mode used when Config.Mode is zero (AT-3, AWS-1).
const DefaultMode fs.FileMode = 0o440

// Config configures one secret provider instance.
type Config struct {
	Name     string        // provider id, for example "atlassian"
	Source   string        // configured secret store name, for example "aws-secretsmanager"
	SecretID string        // key within the store
	Interval time.Duration // re-fetch interval; becomes the credential lifetime
	SinkPath string        // absolute file path; empty means no file sink (served over the socket, AT-2b)
	Mode     fs.FileMode   // zero means DefaultMode
	Owner    string
	Group    string
	Format   domain.SinkFormat // "" means domain.SinkRaw
}

// Provider is the generic secret provider. It is safe for concurrent use: it
// holds no mutable state.
type Provider struct{ cfg Config }

// New validates cfg and returns the provider. Invalid fields yield ErrConfig;
// a sink mode granting any access to "other" or write to group yields
// ErrPolicy (AT-3: never world readable).
func New(cfg Config) (*Provider, error) {
	switch {
	case cfg.Name == "":
		return nil, domain.NewConfigError("name", "required")
	case cfg.Source == "":
		return nil, domain.NewConfigError("source", "required")
	case cfg.SecretID == "":
		return nil, domain.NewConfigError("secret_id", "required")
	case cfg.Interval <= 0:
		return nil, domain.NewConfigError("interval", "must be positive")
	case cfg.Format != "" && cfg.Format != domain.SinkRaw && cfg.Format != domain.SinkRawNL:
		return nil, domain.NewConfigError("sink.format", "unknown format")
	case cfg.SinkPath != "" && !filepath.IsAbs(cfg.SinkPath):
		return nil, domain.NewConfigError("sink.file", "must be an absolute path")
	}
	if cfg.Mode == 0 {
		cfg.Mode = DefaultMode
	}
	if cfg.Mode.Perm() != cfg.Mode || cfg.Mode&0o027 != 0 {
		return nil, domain.Wrap(domain.ErrPolicy, fmt.Errorf("sink mode %04o grants group write or access to others", uint32(cfg.Mode)))
	}
	if cfg.Format == "" {
		cfg.Format = domain.SinkRaw
	}
	return &Provider{cfg: cfg}, nil
}

// Name implements domain.Provider.
func (p *Provider) Name() string { return p.cfg.Name }

// Mint fetches the secret from the store. IssuedAt is now and ExpiresAt is
// now+Interval, the re-fetch horizon the cache schedules against.
func (p *Provider) Mint(ctx context.Context, d domain.Deps) (domain.Credential, error) {
	store, err := d.Store(p.cfg.Source)
	if err != nil {
		return domain.Credential{}, domain.Wrap(domain.ErrConfig, err)
	}
	sv, err := store.Get(ctx, p.cfg.SecretID)
	if err != nil {
		return domain.Credential{}, p.classify(err)
	}
	now := d.Clock().Now()
	c := domain.Credential{
		Kind:      domain.KindStaticSecret,
		Value:     sv.Value,
		IssuedAt:  now,
		ExpiresAt: now.Add(p.cfg.Interval),
		Meta:      map[string]string{MetaVersion: sv.Version},
	}
	if err := c.Validate(); err != nil {
		return domain.Credential{}, err
	}
	return c, nil
}

func (p *Provider) classify(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return domain.NewTransient(err, 0)
	case errors.Is(err, domain.ErrNotFound):
		return domain.Wrap(domain.NewProviderError(p.cfg.Name, errors.New("secret not found")), err)
	case domain.ErrorClass(err) != "unknown":
		return err
	default:
		return domain.NewProviderError(p.cfg.Name, err)
	}
}

// Sinks returns the 0440 file sink (AT-2a), or none when SinkPath is empty.
func (p *Provider) Sinks() []domain.SinkSpec {
	if p.cfg.SinkPath == "" {
		return nil
	}
	return []domain.SinkSpec{{
		Path: p.cfg.SinkPath, Mode: p.cfg.Mode, Owner: p.cfg.Owner, Group: p.cfg.Group, Format: p.cfg.Format,
	}}
}

// Revoke is a no-op: the daemon cannot withdraw a shared service-account key
// (PRD 7.4 concerns); the cache removes the sink file.
func (p *Provider) Revoke(context.Context, domain.Credential) error { return nil }

// Probe checks the credential shape only; there is no Atlassian call here
// because the PRD defines no verification endpoint for the key.
func (p *Provider) Probe(_ context.Context, c domain.Credential) error { return c.Validate() }
