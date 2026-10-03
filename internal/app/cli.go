package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/stainedhead/agent-okta-d/internal/config"
	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/version"
	"github.com/stainedhead/agent-okta-d/pkg/client"
)

// Exit codes beyond domain's (0 ok, 1 failure, 77 revoked, 78 config).
const (
	ExitUsage = 2
	// ExitUnreachable: the daemon socket cannot be reached (PRD: daemon-unreachable is exit 3).
	ExitUnreachable = 3
)

// DefaultConfigPath is used when neither --config nor $AGENT_OKTA_D_CONFIG is set.
const DefaultConfigPath = "/etc/agent-okta-d/config.yaml"

// EnvConfig names the environment variable that selects the config file.
const EnvConfig = "AGENT_OKTA_D_CONFIG"

const usage = `usage: agent-okta-d <command> [flags]

commands:
  run                          start the daemon
  token <provider> [--format raw|json]
                               print the current credential (talks to the socket)
  status [--json]              daemon and per-provider state
  doctor                       end-to-end self-test of config, signer, Okta and providers
  revoke                       withdraw now: stop serving, delete credential files
  env <provider>               print export lines (github, aws)
  credential-helper <provider> get|store|erase
                               git credential protocol (github)
  configure aws|git|gh         print or apply native tool configuration
  enroll github|msgraph|okta   store the agent's user credential / print the public key
  version                      print the version

common flags: --config FILE (default $AGENT_OKTA_D_CONFIG or ` + DefaultConfigPath + `), --socket PATH
`

// Main runs one CLI invocation and returns the process exit code. sigs
// delivers the process signals for `run`; it may be nil for other commands.
func Main(args []string, env Env, sigs <-chan os.Signal) int {
	if len(args) == 0 {
		_, _ = io.WriteString(env.Stderr, usage)
		return ExitUsage
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "run":
		err = cmdRun(rest, env, sigs)
	case "token":
		err = cmdToken(rest, env)
	case "status":
		err = cmdStatus(rest, env)
	case "doctor":
		err = cmdDoctor(rest, env)
	case "revoke":
		err = cmdRevoke(rest, env)
	case "env":
		err = cmdEnv(rest, env)
	case "credential-helper":
		err = cmdCredentialHelper(rest, env)
	case "configure":
		err = cmdConfigure(rest, env)
	case "enroll":
		err = cmdEnroll(rest, env)
	case "version":
		_, _ = fmt.Fprintf(env.Stdout, "agent-okta-d %s\n", version.String())
	case "help", "-h", "--help":
		_, _ = io.WriteString(env.Stdout, usage)
	default:
		_, _ = fmt.Fprintf(env.Stderr, "agent-okta-d: unknown command %q\n\n%s", cmd, usage)
		return ExitUsage
	}
	return report(err, env)
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

// report prints err and maps it to the exit code.
func report(err error, env Env) int {
	if err == nil {
		return domain.ExitOK
	}
	var ue usageError
	if errors.Is(err, flag.ErrHelp) {
		return domain.ExitOK
	}
	if errors.As(err, &ue) || strings.Contains(err.Error(), "flag provided but not defined") {
		_, _ = fmt.Fprintf(env.Stderr, "agent-okta-d: %v\n", err)
		return ExitUsage
	}
	_, _ = fmt.Fprintf(env.Stderr, "agent-okta-d: %v\n", err)
	return exitCode(err)
}

// exitCode extends domain.ExitCode with the client's revoked error.
func exitCode(err error) int {
	switch {
	case errors.Is(err, client.ErrRevoked):
		return domain.ExitRevoked
	case errors.Is(err, client.ErrDaemonUnavailable):
		return ExitUnreachable
	}
	return domain.ExitCode(err)
}

type flags struct {
	*flag.FlagSet
	config string
	socket string
}

// newFlags makes a FlagSet with the common --config and --socket flags.
func newFlags(name string, env Env) *flags {
	f := &flags{FlagSet: flag.NewFlagSet(name, flag.ContinueOnError)}
	f.SetOutput(env.Stderr)
	f.StringVar(&f.config, "config", "", "config file")
	f.StringVar(&f.socket, "socket", "", "daemon socket path")
	return f
}

// parse parses args after nPos leading positionals (so `token github --format
// raw` works) and returns the positionals.
func (f *flags) parse(args []string, nPos int) ([]string, error) {
	var pos []string
	for len(pos) < nPos && len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		pos = append(pos, args[0])
		args = args[1:]
	}
	if err := f.Parse(args); err != nil {
		return nil, err
	}
	if len(pos) < nPos {
		return nil, usageError{fmt.Sprintf("%s needs %d argument(s)", f.Name(), nPos)}
	}
	if f.NArg() > 0 {
		return nil, usageError{fmt.Sprintf("%s: unexpected argument %q", f.Name(), f.Arg(0))}
	}
	return pos, nil
}

func (f *flags) path(env Env) string {
	switch {
	case f.config != "":
		return f.config
	case env.Getenv != nil && env.Getenv(EnvConfig) != "":
		return env.Getenv(EnvConfig)
	}
	return DefaultConfigPath
}

func (f *flags) load(env Env) (*config.Config, error) { return config.Load(f.path(env)) }

func (f *flags) newClient(env Env) DaemonClient { return env.NewClient(f.socket) }

func cmdRun(args []string, env Env, sigs <-chan os.Signal) error {
	f := newFlags("run", env)
	if _, err := f.parse(args, 0); err != nil {
		return err
	}
	cfg, err := f.load(env)
	if err != nil {
		return err
	}
	d, err := New(cfg, env, DefaultRegistry())
	if err != nil {
		return err
	}
	return d.Run(context.Background(), sigs)
}

func cmdDoctor(args []string, env Env) error {
	f := newFlags("doctor", env)
	if _, err := f.parse(args, 0); err != nil {
		return err
	}
	cfg, err := f.load(env)
	if err != nil {
		return err
	}
	d, err := New(cfg, env, DefaultRegistry())
	if err != nil {
		return err
	}
	defer d.Close()
	rep := d.Doctor(context.Background())
	rep.Write(env.Stdout)
	if rep.Failed() {
		return errors.New("doctor: one or more checks failed")
	}
	return nil
}

func execCommand(ctx context.Context, argv []string) error {
	if len(argv) == 0 {
		return errors.New("empty command")
	}
	c := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // argv built from fixed git subcommands
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
}
