package github

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// CredentialSource returns the current github credential, normally by asking
// the daemon over its socket (`token github`). The helper never reads the
// secret store itself.
type CredentialSource func(ctx context.Context) (domain.Credential, error)

// HelperOptions configures the git credential helper (GH-3).
type HelperOptions struct {
	Login   string // username returned to git: the agent's EMU login
	WebBase string // origin git talks to, for example https://github.com
}

// RunCredentialHelper implements the git credential helper protocol on in/out
// for operation op ("get", "store" or "erase"). get answers only for the
// configured origin and prints username=<login>, password=<token>. store and
// erase read their input and do nothing, so git can never overwrite or delete
// the credential. For another origin get prints nothing so git falls through
// to the next helper.
func RunCredentialHelper(ctx context.Context, op string, in io.Reader, out io.Writer, src CredentialSource, opt HelperOptions) error {
	if opt.Login == "" || opt.WebBase == "" {
		return domain.NewConfigError("credential-helper", "login and web base are required")
	}
	switch op {
	case "store", "erase":
		_, _ = io.Copy(io.Discard, in)
		return nil
	case "get":
	default:
		return fmt.Errorf("unknown credential helper operation %q", op)
	}
	attrs := readAttrs(in)
	base, err := url.Parse(opt.WebBase)
	if err != nil || base.Host == "" {
		return domain.NewConfigError("credential-helper", "invalid web base")
	}
	if attrs["protocol"] != base.Scheme || !strings.EqualFold(attrs["host"], base.Host) {
		return nil
	}
	c, err := src(ctx)
	if err != nil {
		return err
	}
	tok := c.Value.Reveal()
	if tok == "" {
		return domain.Wrap(domain.ErrProvider, errors.New("daemon returned an empty github credential"))
	}
	if strings.ContainsAny(tok, "\r\n") || strings.ContainsAny(opt.Login, "\r\n") {
		return domain.Wrap(domain.ErrProvider, errors.New("credential contains a line break"))
	}
	_, err = fmt.Fprintf(out, "username=%s\npassword=%s\n", opt.Login, tok)
	return err
}

func readAttrs(r io.Reader) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			m[k] = v
		}
	}
	return m
}
