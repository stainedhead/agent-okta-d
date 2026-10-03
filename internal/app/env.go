package app

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/config"
	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/ipc"
	awsprov "github.com/stainedhead/agent-okta-d/internal/provider/aws"
	"github.com/stainedhead/agent-okta-d/internal/signer/kms"
	"github.com/stainedhead/agent-okta-d/internal/sink"
	"github.com/stainedhead/agent-okta-d/internal/store/awssm"
	"github.com/stainedhead/agent-okta-d/pkg/client"
)

// Sink is the file sink the daemon needs: atomic writes plus the start and
// stop wipes.
type Sink interface {
	domain.Sink
	WipeStale(ctx context.Context, specs []domain.SinkSpec) error
	RemoveAll(ctx context.Context, specs []domain.SinkSpec) error
}

var _ Sink = (*sink.File)(nil)

// Host is the process identity the user-separation check needs.
type Host interface {
	EUID() int
	// GID is the primary group id.
	GID() int
	PID() int
	// LookupGroup resolves a group name to a gid.
	LookupGroup(name string) (int, error)
}

// DaemonClient is what the client-side commands need from pkg/client.
type DaemonClient interface {
	Credential(ctx context.Context, provider string) (client.Credential, error)
	Refresh(ctx context.Context, provider string) (client.Credential, error)
	Status(ctx context.Context) (client.Status, error)
	Identity(ctx context.Context) (client.Identity, error)
}

// Env holds every seam to the outside world. DefaultEnv fills production
// values; tests replace fields with fakes.
type Env struct {
	Clock    domain.Clock
	HTTP     *http.Client
	Sink     Sink
	PeerCred domain.PeerCredReader
	Host     Host

	// AWS SDK adapters (not part of this build, see doc.go). Nil means the
	// feature answers ErrConfig.
	KMS            func(keyID string) (kms.KMSAPI, error)
	SecretsManager func(cfg *config.Config) (awssm.SecretsManagerAPI, error)
	STS            awsprov.STSClient

	// NewClient builds the daemon client for socket ("" means the default
	// socket or $AGENT_OKTA_D_SOCKET).
	NewClient func(socket string) DaemonClient

	Stdin          io.Reader
	Stdout, Stderr io.Writer

	// Signal sends sig to a process (the revoke command); Sleep waits.
	Signal func(pid int, sig os.Signal) error
	Sleep  func(d time.Duration)
	// Alive reports whether pid is a running process.
	Alive func(pid int) bool
	// Exec runs an external command (configure git --apply).
	Exec func(ctx context.Context, argv []string) error
	// Executable is the absolute path of this binary (configure git, gh).
	Executable func() (string, error)
	// Getenv reads the environment.
	Getenv func(string) string
}

// DefaultEnv returns the production Env.
func DefaultEnv() Env {
	return Env{
		Clock:    RealClock{},
		HTTP:     domain.NoRedirect(&http.Client{Timeout: 15 * time.Second}),
		Sink:     sink.New(),
		PeerCred: ipc.NewPeerCred(),
		Host:     osHost{},
		NewClient: func(socket string) DaemonClient {
			if socket == "" {
				return client.New()
			}
			return client.New(client.WithSocketPath(socket))
		},
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		Signal: func(pid int, sig os.Signal) error {
			p, err := os.FindProcess(pid)
			if err != nil {
				return err
			}
			return p.Signal(sig)
		},
		Sleep: time.Sleep,
		Alive: func(pid int) bool { return syscall.Kill(pid, 0) == nil },
		Exec:  execCommand,
		Executable: func() (string, error) {
			return os.Executable()
		},
		Getenv: os.Getenv,
	}
}

type osHost struct{}

func (osHost) EUID() int { return os.Geteuid() }
func (osHost) GID() int  { return os.Getgid() }
func (osHost) PID() int  { return os.Getpid() }
func (osHost) LookupGroup(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}

// NotifySignals returns a channel delivering the signals the daemon handles
// (TERM and INT stop, USR1 revokes, HUP is logged) and a stop function.
func NotifySignals() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGUSR1, syscall.SIGHUP)
	return ch, func() { signal.Stop(ch) }
}
