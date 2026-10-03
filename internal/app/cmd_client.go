package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	awsprov "github.com/stainedhead/agent-okta-d/internal/provider/aws"
	ghprov "github.com/stainedhead/agent-okta-d/internal/provider/github"
	"github.com/stainedhead/agent-okta-d/pkg/client"
)

func cmdToken(args []string, env Env) error {
	f := newFlags("token", env)
	format := f.String("format", "raw", "raw or json")
	refresh := f.Bool("refresh", false, "force the daemon to refresh first")
	pos, err := f.parse(args, 1)
	if err != nil {
		return err
	}
	if *format != "raw" && *format != "json" {
		return usageError{"token: --format must be raw or json"}
	}
	dc := f.newClient(env)
	get := dc.Credential
	if *refresh {
		get = dc.Refresh
	}
	c, err := get(context.Background(), pos[0])
	if err != nil {
		return explainClientErr(pos[0], err)
	}
	return writeToken(env.Stdout, c, *format)
}

// tokenJSON is the --format json document; unlike client.Credential it carries
// the token because printing it is the point of the command.
type tokenJSON struct {
	TokenType   string    `json:"token_type"`
	AccessToken string    `json:"access_token"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Audience    string    `json:"audience"`
}

func writeToken(w io.Writer, c client.Credential, format string) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(tokenJSON{c.TokenType, c.AccessToken.Reveal(), c.IssuedAt, c.ExpiresAt, c.Audience})
	}
	_, err := fmt.Fprintln(w, c.AccessToken.Reveal())
	return err
}

// explainClientErr adds the operator's next step to the client's typed errors.
func explainClientErr(provider string, err error) error {
	switch {
	case errors.Is(err, client.ErrDaemonUnavailable):
		return fmt.Errorf("the agent-okta-d daemon is unreachable (is it running, and is this user in ipc.allow_gids?): %w", err)
	case errors.Is(err, client.ErrReauthRequired):
		return fmt.Errorf("%s needs re-enrollment: run `agent-okta-d enroll %s`: %w", provider, provider, err)
	case errors.Is(err, client.ErrDegraded):
		if d, ok := client.RetryAfter(err); ok {
			return fmt.Errorf("%s is degraded, retry in %s: %w", provider, d.Round(time.Second), err)
		}
		return fmt.Errorf("%s is degraded: %w", provider, err)
	}
	return err
}

func cmdStatus(args []string, env Env) error {
	f := newFlags("status", env)
	asJSON := f.Bool("json", false, "machine readable output")
	if _, err := f.parse(args, 0); err != nil {
		return err
	}
	ctx := context.Background()
	c := f.newClient(env)
	st, err := c.Status(ctx)
	if err != nil {
		return explainClientErr("daemon", err)
	}
	id, idErr := c.Identity(ctx)
	if *asJSON {
		if err := json.NewEncoder(env.Stdout).Encode(struct {
			Status   client.Status   `json:"status"`
			Identity client.Identity `json:"identity"`
		}{st, id}); err != nil {
			return err
		}
	} else {
		writeStatus(env.Stdout, st, id, idErr)
	}
	switch {
	case st.State == client.StateRevoked:
		return client.ErrRevoked
	case st.State != client.StateValid:
		return fmt.Errorf("daemon state %s", st.State)
	}
	for _, p := range st.Providers {
		if p.State == client.StateDegraded || p.State == client.StateReauthRequired {
			return fmt.Errorf("provider %s is %s", p.Provider, p.State)
		}
	}
	return nil
}

func writeStatus(w io.Writer, st client.Status, id client.Identity, idErr error) {
	_, _ = fmt.Fprintf(w, "daemon: %s\n", st.State)
	if idErr == nil {
		_, _ = fmt.Fprintf(w, "agent: %s  okta client: %s  kid: %s  version: %s\n", id.AgentID, id.OktaClientID, id.KID, id.DaemonVersion)
	}
	for _, p := range st.Providers {
		exp := "-"
		if p.ExpiresAt != nil {
			exp = p.ExpiresAt.UTC().Format(time.RFC3339)
		}
		line := fmt.Sprintf("  %-12s %-16s expires %s", p.Provider, p.State, exp)
		if p.LastError != "" {
			line += "  last_error=" + p.LastError
		}
		if p.RetryAfterSeconds > 0 {
			line += fmt.Sprintf("  retry_after=%ds", p.RetryAfterSeconds)
		}
		if p.State == client.StateReauthRequired {
			line += "  (run `agent-okta-d enroll " + p.Provider + "`)"
		}
		_, _ = fmt.Fprintln(w, line)
	}
}

func cmdEnv(args []string, env Env) error {
	f := newFlags("env", env)
	pos, err := f.parse(args, 1)
	if err != nil {
		return err
	}
	cfg, err := f.load(env)
	if err != nil {
		return err
	}
	switch pos[0] {
	case awsprov.Name:
		out, err := awsprov.EnvSnippet(AWSConfig(cfg))
		if err != nil {
			return err
		}
		_, err = io.WriteString(env.Stdout, out)
		return err
	case ghprov.ProviderName:
		c, err := f.newClient(env).Credential(context.Background(), pos[0])
		if err != nil {
			return explainClientErr(pos[0], err)
		}
		out, err := ghprov.EnvLines(domain.NewSecret(c.AccessToken.Reveal()), GitHubConfig(cfg, env).APIBase)
		if err != nil {
			return err
		}
		_, err = io.WriteString(env.Stdout, out)
		return err
	}
	return usageError{"env: supported providers are aws and github"}
}

func cmdCredentialHelper(args []string, env Env) error {
	f := newFlags("credential-helper", env)
	login := f.String("login", "", "git username (default providers.github.login)")
	webBase := f.String("web-base", "", "origin git talks to (default derived from providers.github.api_base)")
	pos, err := f.parse(args, 2)
	if err != nil {
		return err
	}
	if pos[0] != ghprov.ProviderName {
		return usageError{"credential-helper: only github is supported"}
	}
	opt := ghprov.HelperOptions{Login: *login, WebBase: *webBase}
	if opt.Login == "" || opt.WebBase == "" {
		// The helper runs as the agent user: the config must be readable by it
		// (it holds no secrets) or both flags must be given.
		cfg, err := f.load(env)
		if err != nil {
			return err
		}
		gc := GitHubConfig(cfg, env)
		if opt.Login == "" {
			opt.Login = gc.Login
		}
		if opt.WebBase == "" {
			opt.WebBase = ghprov.WebBase(gc.APIBase)
		}
	}
	c := f.newClient(env)
	src := func(ctx context.Context) (domain.Credential, error) {
		cr, err := c.Credential(ctx, ghprov.ProviderName)
		if err != nil {
			return domain.Credential{}, err
		}
		return domain.Credential{Kind: domain.KindStaticSecret, Value: domain.NewSecret(cr.AccessToken.Reveal())}, nil
	}
	return ghprov.RunCredentialHelper(context.Background(), pos[1], env.Stdin, env.Stdout, src, opt)
}
