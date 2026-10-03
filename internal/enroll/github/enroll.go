// Package github implements `enroll github` (GH-5, GH-6): storing the agent's
// EMU credential, either a pasted PAT or an OAuth device-flow token (RFC 8628),
// in the configured secret store through domain.SecretStore only.
package github

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	ghprov "github.com/stainedhead/agent-okta-d/internal/provider/github"
)

// Options carries what both enrollment modes need.
type Options struct {
	Provider *ghprov.Provider // configured github provider (login, API base, store)
	Deps     domain.Deps      // clock and secret store access
	Out      io.Writer        // operator prompts; never receives a token
}

// Result reports a successful enrollment. It holds no secret.
type Result struct {
	Login     string
	UserID    int64
	ExpiresAt time.Time // zero when unknown (device tokens, PATs without expiry info)
	Version   string    // store version after the write
	Warnings  []string
}

const maxPATBytes = 64 << 10

// EnrollPAT reads a PAT from stdin, verifies it with GET /user (the token must
// belong to providers.github.login), records its expiry and stores it.
// expires, when non-zero, is the operator-supplied expiry; otherwise the
// ASSUMPTION(A-05) response header is used if GitHub sent it.
func EnrollPAT(ctx context.Context, o Options, stdin io.Reader, expires time.Time) (Result, error) {
	cfg := o.Provider.Config()
	if cfg.Mode != ghprov.ModePAT {
		return Result{}, domain.NewConfigError("providers.github.mode", "enroll github --mode pat requires mode: pat")
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, maxPATBytes+1))
	if err != nil {
		return Result{}, fmt.Errorf("reading PAT: %w", err)
	}
	tok := strings.TrimSpace(string(raw))
	switch {
	case len(raw) > maxPATBytes:
		return Result{}, domain.NewConfigError("pat", "input too large")
	case tok == "":
		return Result{}, domain.NewConfigError("pat", "no token on stdin")
	case strings.ContainsAny(tok, " \t\r\n"):
		return Result{}, domain.NewConfigError("pat", "expected a single token")
	}
	secret := domain.NewSecret(tok)
	now := o.Deps.Clock().Now()
	if !expires.IsZero() && !now.Before(expires) {
		return Result{}, domain.NewConfigError("expires", "is already in the past")
	}
	u, err := verify(ctx, o, secret)
	if err != nil {
		return Result{}, err
	}
	if expires.IsZero() {
		expires = u.TokenExpiry // ASSUMPTION(A-05): optional header
	}
	res := Result{Login: u.Login, UserID: u.ID, ExpiresAt: expires}
	switch ghprov.ExpiryStatus(expires, now, cfg.ExpiryWarningDays) {
	case ghprov.ExpiryUnknown:
		res.Warnings = append(res.Warnings, "token expiry unknown: status and doctor cannot warn before it expires; pass the expiry shown in the GitHub UI")
	case ghprov.ExpiryExpired:
		return Result{}, domain.NewConfigError("pat", "token is already expired")
	case ghprov.ExpiryWarn:
		res.Warnings = append(res.Warnings, fmt.Sprintf("token expires in %d days", int(expires.Sub(now).Hours()/24)))
	case ghprov.ExpiryOK:
	}
	res.Version, err = save(ctx, o, ghprov.Stored{Mode: ghprov.ModePAT, Token: tok, ExpiresAt: expires})
	return res, err
}

func verify(ctx context.Context, o Options, tok domain.SecretString) (ghprov.User, error) {
	u, err := o.Provider.Whoami(ctx, tok)
	if err != nil {
		return ghprov.User{}, err
	}
	if want := o.Provider.Config().Login; !strings.EqualFold(u.Login, want) {
		return ghprov.User{}, domain.NewProviderError(ghprov.ProviderName,
			fmt.Errorf("token belongs to %q but providers.github.login is %q; nothing was stored", u.Login, want))
	}
	return u, nil
}

// save writes s with compare-and-set against the current version.
func save(ctx context.Context, o Options, s ghprov.Stored) (string, error) {
	cfg := o.Provider.Config()
	store, err := o.Deps.Store(cfg.StoreName)
	if err != nil {
		return "", err
	}
	sec, err := s.Encode()
	if err != nil {
		return "", err
	}
	ver := ""
	switch cur, gerr := store.Get(ctx, cfg.SecretID); {
	case gerr == nil:
		ver = cur.Version
	case !errors.Is(gerr, domain.ErrNotFound):
		return "", fmt.Errorf("reading existing github secret: %w", gerr)
	}
	nv, err := store.Put(ctx, cfg.SecretID, sec, ver)
	if err != nil {
		return "", fmt.Errorf("storing github credential: %w", err)
	}
	return nv, nil
}
