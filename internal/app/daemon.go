package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/cache"
	"github.com/stainedhead/agent-okta-d/internal/config"
	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/ipc"
	"github.com/stainedhead/agent-okta-d/internal/obs"
	"github.com/stainedhead/agent-okta-d/internal/okta"
	"github.com/stainedhead/agent-okta-d/internal/version"
)

// PidFileName is written next to the socket by `run` so `revoke` can find the
// daemon.
const PidFileName = "agent-okta-d.pid"

const (
	shutdownGrace = 5 * time.Second
	revokeGrace   = 2 * time.Second
)

// Daemon is the assembled credential daemon.
type Daemon struct {
	cfg       *config.Config
	env       Env
	reg       []*Registered
	signer    domain.Signer
	okta      *okta.Client // nil without an Okta-backed provider
	scrub     *domain.Scrubber
	log       *slog.Logger
	audit     *obs.Audit
	cache     *cache.Cache
	deps      *deps
	allowGIDs []int
	warnings  []string
	closeLog  func()
}

// New wires config -> signer -> Okta token source -> cache -> providers. It
// opens nothing that outlives the Daemon except the log destination. Problems
// are classified with the domain taxonomy (ErrConfig -> exit 78).
func New(cfg *config.Config, env Env, reg *Registry) (*Daemon, error) {
	d := &Daemon{cfg: cfg, env: env, scrub: domain.NewScrubber()}
	out, closeLog, err := openLog(cfg.Log.Destination, env)
	if err != nil {
		return nil, err
	}
	d.closeLog = closeLog
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(cfg.Log.Level)); err != nil {
		closeLog()
		return nil, domain.NewConfigError("log.level", "unknown level")
	}
	d.log = obs.NewLogger(out, lvl, d.scrub).With("agent_id", cfg.Agent.ID)
	d.audit = obs.NewAudit(out, cfg.Agent.ID, env.Clock, d.scrub)
	if err := d.assemble(reg); err != nil {
		closeLog()
		return nil, err
	}
	return d, nil
}

func (d *Daemon) assemble(registry *Registry) error {
	var err error
	if d.allowGIDs, err = resolveGIDs(d.cfg.IPC.AllowGIDs, d.env.Host); err != nil {
		return err
	}
	if d.signer, err = NewSigner(d.cfg, d.env); err != nil {
		return err
	}
	regs, err := registry.Build(d.cfg, d.env)
	if err != nil {
		return err
	}
	servers := map[string]okta.AuthServer{}
	for _, r := range regs {
		r.Provider = guarded{Provider: r.Provider, scrub: d.scrub}
		for k, v := range r.OktaServers {
			servers[k] = v
		}
	}
	d.reg = regs
	var src domain.OktaTokenSource = noOkta{}
	if len(servers) > 0 {
		if d.okta, err = okta.NewClient(okta.Config{
			OrgURL: d.cfg.Okta.OrgURL, ClientID: d.cfg.Okta.ClientID, AuthServers: servers,
			Signer: d.signer, Alg: d.cfg.Okta.Signer.Alg, Clock: d.env.Clock, HTTPClient: d.env.HTTP,
		}); err != nil {
			return err
		}
		src = d.okta
	}
	c := d.cfg
	d.cache, err = cache.New(cache.Config{
		Clock: d.env.Clock, Sink: d.env.Sink, Audit: d.audit, Log: d.log, AgentID: c.Agent.ID,
		Fraction: c.Refresh.Fraction, Jitter: c.Refresh.Jitter,
		MinMargin: time.Duration(c.Refresh.MinMarginSeconds) * time.Second,
	})
	if err != nil {
		return err
	}
	d.deps = &deps{
		clock: d.env.Clock, okta: src, cache: d.cache, stores: d.newStores(c),
		log: d.log, audit: d.audit,
	}
	d.cache.SetDeps(d.deps)
	return nil
}

func resolveGIDs(entries []string, h Host) ([]int, error) {
	var out []int
	for i, e := range entries {
		if n, err := strconv.Atoi(e); err == nil {
			out = append(out, n)
			continue
		}
		n, err := h.LookupGroup(e)
		if err != nil {
			return nil, domain.NewConfigError(fmt.Sprintf("ipc.allow_gids[%d]", i), "unknown group")
		}
		out = append(out, n)
	}
	return out, nil
}

func openLog(dest string, env Env) (io.Writer, func(), error) {
	switch dest {
	case "stderr":
		return env.Stderr, func() {}, nil
	case "stdout":
		return env.Stdout, func() {}, nil
	}
	if !filepath.IsAbs(dest) {
		return nil, nil, domain.NewConfigError("log.destination", "must be stderr, stdout or an absolute file path")
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // operator-configured log path
	if err != nil {
		return nil, nil, domain.NewConfigError("log.destination", "cannot open log file")
	}
	return f, func() { _ = f.Close() }, nil
}

func (d *Daemon) guard(fn func() error) error { return obs.Guard(d.log, d.scrub, fn) }

// SinkSpecs lists every credential file of the configured providers.
func (d *Daemon) SinkSpecs() []domain.SinkSpec { return SinkSpecs(d.reg) }

// SelfTest runs the startup self-test without probes.
func (d *Daemon) SelfTest(ctx context.Context) (Report, error) {
	rep, _, fatal := d.selfTest(ctx, false)
	return rep, fatal
}

// Doctor runs the self-test with every provider's end-to-end probe (FR-9).
func (d *Daemon) Doctor(ctx context.Context) Report {
	rep, _, fatal := d.selfTest(ctx, true)
	if fatal != nil {
		rep.Checks = append(rep.Checks, Check{"abort", StatusFail, "doctor stopped at the first fatal check"})
	}
	return rep
}

// Close releases the log destination.
func (d *Daemon) Close() { d.closeLog() }

// Cache exposes the credential cache (tests, wiring).
func (d *Daemon) Cache() *cache.Cache { return d.cache }

// PidFile is the pidfile path for cfg.
func PidFile(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(cfg.IPC.Socket), PidFileName)
}

// Run starts the daemon and blocks until it stops. It returns nil after a
// graceful stop (SIGTERM, SIGINT or ctx cancel) and an error wrapping
// domain.ErrRevoked after the revoke sequence (exit 77). Startup problems
// return ErrConfig (78), ErrPolicy or the failing error. sigs delivers the
// process signals: TERM and INT stop, USR1 revokes, HUP is logged (hot reload
// is a deferred P1 item).
func (d *Daemon) Run(ctx context.Context, sigs <-chan os.Signal) error {
	defer d.closeLog()
	started, err := d.start(ctx)
	if err != nil {
		return err
	}
	return started.wait(ctx, sigs)
}

type running struct {
	d      *Daemon
	srv    *ipc.Server
	ln     interface{ Close() error }
	serve  chan error
	cancel context.CancelFunc
	pid    string
}

func (d *Daemon) start(ctx context.Context) (*running, error) {
	specs := d.SinkSpecs()
	if err := d.env.Sink.WipeStale(ctx, specs); err != nil {
		return nil, fmt.Errorf("wipe stale sinks: %w", err)
	}
	rep, refuse, fatal := d.selfTest(ctx, false)
	for _, c := range rep.Checks {
		lvl := slog.LevelInfo
		switch c.Status {
		case StatusWarn:
			lvl = slog.LevelWarn
		case StatusFail:
			lvl = slog.LevelError
		}
		d.log.Log(ctx, lvl, "self-test", "check", c.Name, "status", c.Status, "detail", c.Detail)
	}
	if fatal != nil {
		if errors.Is(fatal, domain.ErrAuthDefinitive) {
			// Okta rejects the client outright (app disabled or key removed):
			// the kill switch. Exit 77 so supervisors do not restart-loop.
			d.audit.Emit(ctx, domain.AuditEvent{TS: d.env.Clock.Now(), Event: domain.AuditStart, Result: domain.ResultError, ErrorClass: domain.ErrorClass(fatal)})
			return nil, domain.Wrap(domain.ErrRevoked, fatal)
		}
		return nil, fatal
	}
	registered := 0
	for _, r := range d.reg {
		name := r.Provider.Name()
		if err, bad := refuse[name]; bad {
			d.log.Error("provider refused: self-test failed", "provider", name, "error", d.errText(err))
			d.audit.Emit(ctx, domain.AuditEvent{TS: d.env.Clock.Now(), Event: domain.AuditFailure, Provider: name, Result: domain.ResultError, ErrorClass: domain.ErrorClass(err), Detail: "self-test: provider not served"})
			continue
		}
		if err := d.cache.Register(r.Provider, r.Key, r.Options); err != nil {
			return nil, err
		}
		registered++
	}
	switch {
	case len(d.reg) == 0:
		return nil, domain.NewConfigError("providers", "no provider is configured")
	case registered == 0:
		return nil, fmt.Errorf("every provider failed the self-test: %w", domain.ErrProvider)
	}
	return d.listen(ctx)
}

func (d *Daemon) listen(ctx context.Context) (*running, error) {
	sock := d.cfg.IPC.Socket
	if err := os.MkdirAll(filepath.Dir(sock), 0o750); err != nil {
		return nil, fmt.Errorf("socket directory: %w", err)
	}
	if err := ipc.CheckSocketDir(filepath.Dir(sock)); err != nil { // FR-R04
		return nil, err
	}
	mode := os.FileMode(0o660)
	if len(d.allowGIDs) > 1 {
		mode = 0o666 // several groups: peer credentials and the allow-list decide
	}
	ln, err := ipc.ListenUnix(sock, mode)
	if err != nil {
		return nil, err
	}
	if len(d.allowGIDs) == 1 {
		if err := os.Chown(sock, -1, d.allowGIDs[0]); err != nil {
			_ = ln.Close()
			return nil, domain.Wrap(domain.ErrPolicy, fmt.Errorf("cannot give group %d access to the socket (the daemon user must be a member): %w", d.allowGIDs[0], err))
		}
	}
	pid := PidFile(d.cfg)
	if err := os.WriteFile(pid, []byte(strconv.Itoa(d.env.Host.PID())+"\n"), 0o644); err != nil { //nolint:gosec // pid is not secret
		_ = ln.Close()
		return nil, fmt.Errorf("write pidfile: %w", err)
	}
	srv := ipc.New(ipc.Config{
		AllowGIDs: d.allowGIDs, AgentID: d.cfg.Agent.ID,
		Identity: domain.WireIdentity{
			AgentID: d.cfg.Agent.ID, OktaClientID: d.cfg.Okta.ClientID, KID: d.cfg.Okta.Signer.KID,
			DaemonVersion: version.Version, APIVersion: domain.APIVersion,
		},
	}, ipc.Deps{
		Backend: backend{c: d.cache, clock: d.env.Clock}, PeerCred: d.env.PeerCred, Audit: d.audit,
		Clock: d.env.Clock, Logger: d.log,
	})
	r := &running{d: d, srv: srv, ln: ln, serve: make(chan error, 1), pid: pid}
	go func() { r.serve <- srv.Serve(ln) }()
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	r.cancel = cancel
	go d.cache.Run(runCtx)
	d.audit.Emit(ctx, domain.AuditEvent{TS: d.env.Clock.Now(), Event: domain.AuditStart, Result: domain.ResultOK, Detail: "version " + version.Version})
	d.log.Info("started", "socket", sock, "version", version.Version)
	return r, nil
}

func (r *running) wait(ctx context.Context, sigs <-chan os.Signal) error {
	d := r.d
	for {
		select {
		case <-ctx.Done():
			return r.stop()
		case err := <-r.serve:
			r.cleanup()
			if err == nil {
				err = errors.New("api server stopped unexpectedly")
			}
			return err
		case <-d.cache.Revoked():
			return r.revoked("automatic")
		case sig := <-sigs:
			switch sig {
			case syscall.SIGUSR1:
				d.cache.Revoke(ctx)
				return r.revoked("manual")
			case syscall.SIGHUP:
				d.log.Warn("SIGHUP ignored: hot reload is not implemented")
			default:
				return r.stop()
			}
		}
	}
}

func (r *running) cleanup() {
	r.cancel()
	_ = os.Remove(r.pid)
	_ = r.ln.Close()
}

// stop is the graceful shutdown: stop serving, remove the sinks, exit 0.
func (r *running) stop() error {
	d := r.d
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	_ = r.srv.Shutdown(ctx)
	r.cleanup()
	d.cache.Close()
	err := d.env.Sink.RemoveAll(ctx, d.SinkSpecs())
	d.log.Info("stopped")
	return err
}

// revoked finishes the withdraw sequence (PRD 13). The cache already did steps
// 1 to 3 (state revoked so every caller gets 403, sinks removed, provider
// Revoke hooks run); this adds a final sink sweep, step 4 (forget in-memory
// secrets), step 5 (the critical audit event) and returns the error that makes
// the process exit 77 (step 6).
func (r *running) revoked(reason string) error {
	d := r.d
	ctx, cancel := context.WithTimeout(context.Background(), revokeGrace)
	defer cancel()
	_ = d.env.Sink.RemoveAll(ctx, d.SinkSpecs())
	_ = r.srv.Shutdown(ctx)
	r.cleanup()
	d.cache.Close()
	d.scrub.Reset()
	d.audit.Emit(ctx, domain.AuditEvent{
		TS: d.env.Clock.Now(), Event: domain.AuditRevoke, Result: domain.ResultError, ErrorClass: "revoked",
		Detail: "CRITICAL withdraw complete (" + reason + "): exiting 77",
	})
	d.log.Error("revoked: withdraw complete", "reason", reason)
	return fmt.Errorf("daemon revoked (%s): %w", reason, domain.ErrRevoked)
}

// newStores builds the store set with the scrubber attached (FR-R06).
func (d *Daemon) newStores(c *config.Config) *storeSet {
	ss := newStoreSet(c, d.env, d.signer)
	ss.scrub = d.scrub
	return ss
}
