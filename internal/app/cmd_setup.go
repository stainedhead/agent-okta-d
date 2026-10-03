package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/config"
	"github.com/stainedhead/agent-okta-d/internal/domain"
	enrollgh "github.com/stainedhead/agent-okta-d/internal/enroll/github"
	enrollmg "github.com/stainedhead/agent-okta-d/internal/enroll/msgraph"
	awsprov "github.com/stainedhead/agent-okta-d/internal/provider/aws"
	ghprov "github.com/stainedhead/agent-okta-d/internal/provider/github"
)

func cmdConfigure(args []string, env Env) error {
	if len(args) == 0 {
		return usageError{"configure needs one of: aws, git, gh"}
	}
	switch args[0] {
	case "aws":
		return configureAWS(args[1:], env)
	case "git":
		return configureGit(args[1:], env)
	case "gh":
		return configureGH(args[1:], env)
	}
	return usageError{"configure needs one of: aws, git, gh"}
}

func configureAWS(args []string, env Env) error {
	f := newFlags("configure aws", env)
	asEnv := f.Bool("env", false, "print export lines instead of a profile")
	write := f.String("write", "", "append the profile to this AWS config file instead of printing it")
	if _, err := f.parse(args, 0); err != nil {
		return err
	}
	cfg, err := f.load(env)
	if err != nil {
		return err
	}
	ac := AWSConfig(cfg)
	if cfg.Providers.AWS == nil {
		return domain.NewConfigError("providers.aws", "not configured")
	}
	if *asEnv {
		out, err := awsprov.EnvSnippet(ac)
		if err != nil {
			return err
		}
		_, err = io.WriteString(env.Stdout, out)
		return err
	}
	out, err := awsprov.ProfileSnippet(ac)
	if err != nil {
		return err
	}
	if *write == "" {
		_, err = io.WriteString(env.Stdout, out)
		return err
	}
	return appendProfile(*write, out, env.Stdout)
}

// appendProfile adds the profile to path unless it is already there.
func appendProfile(path, snippet string, w io.Writer) error {
	existing, err := os.ReadFile(path) //nolint:gosec // operator-chosen path
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if strings.Contains(string(existing), "[profile "+awsprov.ProfileName+"]") {
		return fmt.Errorf("%s already has [profile %s]; edit it by hand", path, awsprov.ProfileName)
	}
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // operator-chosen path
	if err != nil {
		return err
	}
	prefix := ""
	if len(existing) > 0 && !strings.HasSuffix(string(existing), "\n") {
		prefix = "\n"
	}
	if _, err := io.WriteString(fh, prefix+snippet); err != nil {
		_ = fh.Close()
		return err
	}
	if err := fh.Close(); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "wrote [profile %s] to %s\n", awsprov.ProfileName, path)
	return nil
}

func configureGit(args []string, env Env) error {
	f := newFlags("configure git", env)
	apply := f.Bool("apply", false, "run git config --system instead of printing the snippet")
	noIdentity := f.Bool("no-identity", false, "only configure the credential helper, skip user.name and user.email")
	if _, err := f.parse(args, 0); err != nil {
		return err
	}
	cfg, err := f.load(env)
	if err != nil {
		return err
	}
	if cfg.Providers.GitHub == nil {
		return domain.NewConfigError("providers.github", "not configured")
	}
	gc := GitHubConfig(cfg, env)
	bin, err := env.Executable()
	if err != nil {
		return err
	}
	var id ghprov.GitIdentity
	if !*noIdentity {
		// GH-8: the numeric user id for the noreply address comes from GET /user.
		p, err := ghprov.New(gc)
		if err != nil {
			return err
		}
		cr, err := f.newClient(env).Credential(context.Background(), ghprov.ProviderName)
		if err != nil {
			return explainClientErr(ghprov.ProviderName, err)
		}
		if id, err = p.ResolveGitIdentity(context.Background(), domain.NewSecret(cr.AccessToken.Reveal())); err != nil {
			return err
		}
	}
	web := ghprov.WebBase(gc.APIBase)
	if !*apply {
		out, err := ghprov.GitConfigSnippet(bin, web, id)
		if err != nil {
			return err
		}
		_, err = io.WriteString(env.Stdout, out)
		return err
	}
	if _, err := ghprov.GitConfigSnippet(bin, web, id); err != nil { // validate inputs
		return err
	}
	for _, argv := range ghprov.GitConfigCommands(bin, web, id) {
		if err := env.Exec(context.Background(), argv); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(argv[:min(len(argv), 4)], " "), err)
		}
	}
	_, _ = fmt.Fprintln(env.Stdout, "git configured (system level)")
	return nil
}

func configureGH(args []string, env Env) error {
	f := newFlags("configure gh", env)
	ghPath := f.String("gh-path", "", "absolute path of the real gh binary")
	output := f.String("output", "", "write the shim to this file (mode 0755) instead of printing it")
	if _, err := f.parse(args, 0); err != nil {
		return err
	}
	if *ghPath == "" {
		return usageError{"configure gh: --gh-path (absolute path of the real gh) is required"}
	}
	bin, err := env.Executable()
	if err != nil {
		return err
	}
	script, err := ghprov.ShimScript(bin, *ghPath)
	if err != nil {
		return err
	}
	if *output == "" {
		_, err = io.WriteString(env.Stdout, script)
		return err
	}
	if err := writeExecutable(*output, script); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(env.Stdout, "wrote gh shim to %s\n", *output)
	return nil
}

// writeExecutable writes content to path atomically with mode 0755.
func writeExecutable(path, content string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".gh-shim-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil { //nolint:gosec // an executable shim must be executable
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func cmdEnroll(args []string, env Env) error {
	if len(args) == 0 {
		return usageError{"enroll needs one of: github, msgraph, okta"}
	}
	switch args[0] {
	case "github":
		return enrollGitHub(args[1:], env)
	case "msgraph":
		return enrollMSGraph(args[1:], env)
	case "okta":
		return enrollOkta(args[1:], env)
	}
	return usageError{"enroll needs one of: github, msgraph, okta"}
}

// enrollDaemon builds the daemon wiring without running it: enrollment only
// needs the stores, the clock and the signer.
func enrollDaemon(f *flags, env Env) (*config.Config, *Daemon, error) {
	cfg, err := f.load(env)
	if err != nil {
		return nil, nil, err
	}
	d, err := New(cfg, env, DefaultRegistry())
	if err != nil {
		return nil, nil, err
	}
	return cfg, d, nil
}

func enrollGitHub(args []string, env Env) error {
	f := newFlags("enroll github", env)
	mode := f.String("mode", "", "pat or oauth_device (must match providers.github.mode)")
	expires := f.String("expires", "", "PAT expiry as YYYY-MM-DD (as shown in the GitHub UI)")
	if _, err := f.parse(args, 0); err != nil {
		return err
	}
	cfg, d, err := enrollDaemon(f, env)
	if err != nil {
		return err
	}
	defer d.Close()
	if cfg.Providers.GitHub == nil {
		return domain.NewConfigError("providers.github", "not configured")
	}
	if *mode != "" && *mode != cfg.Providers.GitHub.Mode {
		return domain.NewConfigError("providers.github.mode", "config says "+cfg.Providers.GitHub.Mode+", not "+*mode)
	}
	p, err := ghprov.New(GitHubConfig(cfg, env))
	if err != nil {
		return err
	}
	o := enrollgh.Options{Provider: p, Deps: d.deps, Out: env.Stdout}
	ctx := context.Background()
	var res enrollgh.Result
	if cfg.Providers.GitHub.Mode == string(ghprov.ModePAT) {
		var exp time.Time
		if *expires != "" {
			if exp, err = time.Parse(time.DateOnly, *expires); err != nil {
				return usageError{"enroll github: --expires must be YYYY-MM-DD"}
			}
		}
		_, _ = fmt.Fprintln(env.Stdout, "reading the PAT from stdin...")
		res, err = enrollgh.EnrollPAT(ctx, o, env.Stdin, exp)
	} else {
		res, err = enrollgh.EnrollDevice(ctx, o, enrollgh.DeviceOptions{})
	}
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(env.Stdout, "enrolled github user %s\n", res.Login)
	for _, w := range res.Warnings {
		_, _ = fmt.Fprintln(env.Stdout, "warning:", w)
	}
	nudge(ctx, f, env, ghprov.ProviderName)
	return nil
}

func enrollMSGraph(args []string, env Env) error {
	f := newFlags("enroll msgraph", env)
	if _, err := f.parse(args, 0); err != nil {
		return err
	}
	cfg, d, err := enrollDaemon(f, env)
	if err != nil {
		return err
	}
	defer d.Close()
	m := cfg.Providers.MSGraph
	if m == nil {
		return domain.NewConfigError("providers.msgraph", "not configured")
	}
	store, err := d.deps.Store(m.Store.Type)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if err := enrollmg.Enroll(ctx, enrollmg.Config{
		TenantID: m.TenantID, ClientID: m.AppClientID, Scopes: m.Scopes, ExpectedUPN: m.UPN,
		Store: store, SecretID: m.Store.SecretID, Clock: env.Clock, Out: env.Stdout, HTTP: env.HTTP,
	}); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(env.Stdout, "enrolled %s\n", m.UPN)
	nudge(ctx, f, env, "msgraph")
	return nil
}

// nudge asks a running daemon to leave reauth_required (best effort: the
// operator running enroll is usually not in ipc.allow_gids).
func nudge(ctx context.Context, f *flags, env Env, provider string) {
	if _, err := f.newClient(env).Refresh(ctx, provider); err == nil {
		_, _ = fmt.Fprintf(env.Stdout, "daemon refreshed %s\n", provider)
		return
	}
	_, _ = fmt.Fprintf(env.Stdout, "the daemon was not told to refresh %s; it picks up the credential on its next retry, or run `agent-okta-d token %s --refresh` as the agent\n", provider, provider)
}

func enrollOkta(args []string, env Env) error {
	f := newFlags("enroll okta", env)
	if _, err := f.parse(args, 0); err != nil {
		return err
	}
	cfg, d, err := enrollDaemon(f, env)
	if err != nil {
		return err
	}
	defer d.Close()
	jwk, err := d.signer.Public()
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(env.Stdout, "Public key (JWK) for the Okta API Services app %s, kid %s:\n%s\n\n", cfg.Okta.ClientID, cfg.Okta.Signer.KID, jwk)
	_, _ = fmt.Fprintln(env.Stdout, `Onboarding checklist:
  1. Okta admin: create an API Services app, authentication "Public key / Private key", add the JWK above.
  2. Grant the scopes of each authorization server the agent uses; restrict the access policy to this client.
  3. Set okta.client_id in the daemon config, then run: agent-okta-d doctor`)
	return nil
}
