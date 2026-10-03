package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/okta"
	ghprov "github.com/stainedhead/agent-okta-d/internal/provider/github"
	"github.com/stainedhead/agent-okta-d/internal/version"
)

// Check outcomes.
const (
	StatusOK   = "ok"
	StatusWarn = "warn"
	StatusFail = "fail"
	StatusSkip = "skip"
)

// Check is one self-test or doctor line. Detail never carries a secret.
type Check struct {
	Name   string
	Status string
	Detail string
}

// Report is the result of a self-test run.
type Report struct{ Checks []Check }

// Failed reports whether any check failed.
func (r Report) Failed() bool {
	return slices.ContainsFunc(r.Checks, func(c Check) bool { return c.Status == StatusFail })
}

// Write renders the report, one line per check.
func (r Report) Write(w io.Writer) {
	for _, c := range r.Checks {
		_, _ = fmt.Fprintf(w, "[%-4s] %s: %s\n", c.Status, c.Name, c.Detail)
	}
}

const mintTimeout = 30 * time.Second

// selfTest runs the FR-9 checks. With probe it also runs every provider's end
// to end Probe (doctor); the startup self-test leaves probes out. It returns
// the report, the providers to refuse to serve and a fatal error (the daemon
// must not start).
func (d *Daemon) selfTest(ctx context.Context, probe bool) (rep Report, refuse map[string]error, fatal error) {
	refuse = map[string]error{}
	add := func(name, status, detail string) { rep.Checks = append(rep.Checks, Check{name, status, detail}) }

	add("version", StatusOK, version.String())
	for _, w := range d.cfg.Warnings() {
		add("config", StatusWarn, w)
	}
	for _, w := range d.warnings {
		add("config", StatusWarn, w)
	}

	if c := d.separation(); c.Status == StatusFail {
		rep.Checks = append(rep.Checks, c)
		return rep, refuse, domain.Wrap(domain.ErrPolicy, errors.New(c.Detail))
	} else {
		rep.Checks = append(rep.Checks, c)
	}

	if _, err := d.signer.Public(); err != nil {
		add("signer", StatusFail, d.errText(err))
		return rep, refuse, err
	}
	add("signer", StatusOK, d.cfg.Okta.Signer.Type+" signer ready, kid "+d.cfg.Okta.Signer.KID)
	if d.cfg.Okta.Signer.Type == "file" {
		// FR-R01 (in scope part): the only signer in this build keeps the private
		// key on disk readable by the daemon uid, which weakens goal G1.
		add("signer-hardening", StatusWarn, "file signer is for dev only: the private key is readable by the daemon uid; production needs a KMS, Keychain or TPM signer (not yet available in this build)")
	}

	if d.okta != nil {
		skew, err := d.okta.CheckSkew(ctx)
		switch {
		case err == nil:
			add("okta-clock-skew", StatusOK, "skew "+skew.Round(time.Second).String())
		case errors.Is(err, okta.ErrClockSkew):
			add("okta-clock-skew", StatusFail, d.errText(err))
			return rep, refuse, err
		default:
			add("okta-clock-skew", StatusWarn, "not checked: "+d.errText(err))
		}
	} else {
		add("okta-clock-skew", StatusSkip, "no Okta-backed provider configured")
	}

	for _, r := range d.reg {
		name := "provider:" + r.Provider.Name()
		cred, err := d.mintCheck(ctx, r.Provider)
		switch {
		case err == nil:
			add(name, StatusOK, "mint ok, expires "+cred.ExpiresAt.UTC().Format(time.RFC3339))
			if warn, ok := expiryWarning(unwrap(r.Provider), cred, d.env.Clock.Now()); ok {
				add(name, StatusWarn, warn)
			}
			if probe {
				if perr := d.probeCheck(ctx, r.Provider, cred); perr != nil {
					add(name+":probe", StatusFail, d.errText(perr))
					refuse[r.Provider.Name()] = perr
				} else {
					add(name+":probe", StatusOK, "end-to-end probe ok")
				}
			}
		case errors.Is(err, domain.ErrAuthDefinitive):
			add(name, StatusFail, d.errText(err))
			return rep, refuse, err
		case errors.Is(err, domain.ErrReauthRequired):
			add(name, StatusWarn, "reauth_required: run `agent-okta-d enroll "+r.Provider.Name()+"`")
		case errors.Is(err, domain.ErrTransient):
			add(name, StatusWarn, "transient, will retry with backoff: "+d.errText(err))
		default:
			add(name, StatusFail, d.errText(err))
			refuse[r.Provider.Name()] = err
		}
	}
	return rep, refuse, nil
}

func (d *Daemon) mintCheck(ctx context.Context, p domain.Provider) (domain.Credential, error) {
	ctx, cancel := context.WithTimeout(ctx, mintTimeout)
	defer cancel()
	var cred domain.Credential
	err := d.guard(func() (e error) {
		cred, e = p.Mint(ctx, d.deps)
		if e == nil {
			e = cred.Validate()
		}
		return e
	})
	return cred, err
}

func (d *Daemon) probeCheck(ctx context.Context, p domain.Provider, c domain.Credential) error {
	ctx, cancel := context.WithTimeout(ctx, mintTimeout)
	defer cancel()
	return d.guard(func() error { return p.Probe(ctx, c) })
}

// expiryWarning asks providers that track a user-credential expiry (github)
// for a warning.
func expiryWarning(p domain.Provider, c domain.Credential, now time.Time) (string, bool) {
	if g, ok := p.(*ghprov.Provider); ok {
		return g.ExpiryWarning(c, now)
	}
	return "", false
}

// separation checks the agent/daemon user separation (PRD risk 3): the daemon
// must not run in a group that ipc.allow_gids admits, because then everything
// the agent can read the daemon can read and vice versa. Supplementary
// membership is allowed (the daemon needs it to chgrp 0440 sinks).
func (d *Daemon) separation() Check {
	h := d.env.Host
	if slices.Contains(d.allowGIDs, h.GID()) {
		return Check{"user-separation", StatusFail, fmt.Sprintf("the daemon's primary gid %d is listed in ipc.allow_gids: run the daemon as its own user and group, separate from the agent", h.GID())}
	}
	if h.EUID() == 0 {
		return Check{"user-separation", StatusWarn, "running as root: run the daemon as an unprivileged user separate from the agent"}
	}
	return Check{"user-separation", StatusOK, fmt.Sprintf("daemon uid %d gid %d is outside ipc.allow_gids", h.EUID(), h.GID())}
}

// errText renders an error for operators on one line, scrubbed once more as a
// backstop (errors in this code base never carry secrets).
func (d *Daemon) errText(err error) string {
	return d.scrub.Scrub(strings.ReplaceAll(err.Error(), "\n", " "))
}
