package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/config"
)

const (
	revokePoll    = 100 * time.Millisecond
	revokeTimeout = 15 * time.Second
)

func cmdRevoke(args []string, env Env) error {
	f := newFlags("revoke", env)
	timeout := f.Duration("timeout", revokeTimeout, "how long to wait for the daemon to exit")
	if _, err := f.parse(args, 0); err != nil {
		return err
	}
	cfg, err := f.load(env)
	if err != nil {
		return err
	}
	return Revoke(context.Background(), cfg, env, *timeout)
}

// Revoke executes the withdraw sequence now (PRD 13, FR-16). There is no
// revoke endpoint in the API, so it signals the daemon (SIGUSR1) through the
// pidfile, waits for it to exit (it runs steps 1 to 6 and exits 77), and then
// wipes the credential files itself, so it also works when the daemon is
// already down or wedged.
func Revoke(ctx context.Context, cfg *config.Config, env Env, timeout time.Duration) error {
	out := env.Stdout
	var waitErr, notDaemon error
	pid, perr := readPid(PidFile(cfg))
	switch {
	case perr != nil && !errors.Is(perr, os.ErrNotExist):
		return fmt.Errorf("revoke: %w", perr)
	case perr != nil || !env.Alive(pid):
		_, _ = fmt.Fprintln(out, "no running daemon found; wiping credential files")
	case !daemonVerified(cfg, env, pid):
		// FR-R03: a stale pidfile plus PID reuse must never make revoke signal
		// an unrelated process. The sinks are still wiped below.
		notDaemon = fmt.Errorf("revoke: pidfile names live pid %d but the daemon socket does not confirm it; not signaling (check for a running agent-okta-d manually)", pid)
		_, _ = fmt.Fprintf(out, "pid %d is not the daemon; wiping credential files\n", pid)
	default:
		if err := env.Signal(pid, syscall.SIGUSR1); err != nil {
			return fmt.Errorf("revoke: signal daemon: %w", err)
		}
		_, _ = fmt.Fprintf(out, "sent revoke to daemon pid %d\n", pid)
		waited := time.Duration(0)
		for env.Alive(pid) && waited < timeout {
			env.Sleep(revokePoll)
			waited += revokePoll
		}
		if env.Alive(pid) {
			waitErr = fmt.Errorf("daemon pid %d did not exit within %s", pid, timeout)
		}
	}
	regs, err := DefaultRegistry().Build(cfg, env)
	if err != nil {
		return err
	}
	specs := SinkSpecs(regs)
	if err := env.Sink.RemoveAll(ctx, specs); err != nil {
		return fmt.Errorf("revoke: remove credential files: %w", err)
	}
	_, _ = fmt.Fprintf(out, "removed %d credential file(s)\n", len(specs))
	if notDaemon != nil {
		return notDaemon
	}
	if waitErr != nil {
		return waitErr
	}
	_, _ = fmt.Fprintln(out, "revoked. Next: disable the Okta app, then the agent's AD/Okta user (see PRD section 13 runbook)")
	return nil
}

func readPid(path string) (int, error) {
	b, err := os.ReadFile(path) //nolint:gosec // derived from the configured socket directory
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n <= 0 {
		return 0, errors.New("pidfile is malformed")
	}
	return n, nil
}

// daemonVerified reports whether pid is the process listening on the daemon
// socket.
func daemonVerified(cfg *config.Config, env Env, pid int) bool {
	if env.DaemonPID == nil {
		return false
	}
	got, err := env.DaemonPID(cfg.IPC.Socket)
	return err == nil && got == pid
}

// writePidFile replaces any stale pidfile with a fresh 0640 one.
func writePidFile(path string, pid int) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640) //nolint:gosec // group-readable so the operator's revoke can read it
	if err != nil {
		return err
	}
	if _, err := f.WriteString(strconv.Itoa(pid) + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
