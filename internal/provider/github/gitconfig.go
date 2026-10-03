package github

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// GitIdentity is the user.name / user.email pair for the agent's commits.
type GitIdentity struct {
	Name  string
	Email string
}

func singleLine(s string) bool { return !strings.ContainsAny(s, "\r\n\x00") }

func helperValue(agentBin string) string {
	return "!" + ShellQuote(agentBin) + " credential-helper github"
}

// GitConfigSnippet renders the system gitconfig for `configure git` (GH-3,
// GH-8): the credential helper for webBase (the empty `helper =` first clears
// inherited helpers) and, when id is set, user.name and user.email.
func GitConfigSnippet(agentBin, webBase string, id GitIdentity) (string, error) {
	if err := checkGitInputs(agentBin, webBase, id); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[credential %s]\n\thelper =\n\thelper = %s\n", strconv.Quote(webBase), helperValue(agentBin))
	if id.Name != "" || id.Email != "" {
		b.WriteString("[user]\n")
		if id.Name != "" {
			fmt.Fprintf(&b, "\tname = %s\n", id.Name)
		}
		if id.Email != "" {
			fmt.Fprintf(&b, "\temail = %s\n", id.Email)
		}
	}
	return b.String(), nil
}

func checkGitInputs(agentBin, webBase string, id GitIdentity) error {
	switch {
	case agentBin == "" || !singleLine(agentBin):
		return domain.NewConfigError("agent-okta-d path", "must be a non-empty single-line path")
	case webBase == "" || !singleLine(webBase) || strings.Contains(webBase, `"`):
		return domain.NewConfigError("github web base", "must be a non-empty single-line URL")
	case !singleLine(id.Name):
		return domain.NewConfigError("git_identity.name", "must be a single line")
	case !singleLine(id.Email):
		return domain.NewConfigError("git_identity.email", "must be a single line")
	}
	return nil
}

// GitConfigCommands returns the equivalent `git config --system` invocations
// (argv, including "git") so the CLI can apply the configuration itself.
func GitConfigCommands(agentBin, webBase string, id GitIdentity) [][]string {
	key := "credential." + webBase + ".helper"
	cmds := [][]string{
		{"git", "config", "--system", "--replace-all", key, ""},
		{"git", "config", "--system", "--add", key, helperValue(agentBin)},
	}
	if id.Name != "" {
		cmds = append(cmds, []string{"git", "config", "--system", "user.name", id.Name})
	}
	if id.Email != "" {
		cmds = append(cmds, []string{"git", "config", "--system", "user.email", id.Email})
	}
	return cmds
}

// ResolveGitIdentity builds the commit identity (GH-8). Name defaults to the
// login. Email defaults to, and may contain the placeholders <id> and <login>
// in, the noreply form <id>+<login>@users.noreply.github.com, where the id
// comes from GET /user. It also verifies the token belongs to the configured
// login. ASSUMPTION(A-05): the noreply form is unconfirmed for EMU/GHE.com.
func (p *Provider) ResolveGitIdentity(ctx context.Context, token domain.SecretString) (GitIdentity, error) {
	u, err := p.api.User(ctx, token)
	if err != nil {
		return GitIdentity{}, err
	}
	if !strings.EqualFold(u.Login, p.cfg.Login) {
		return GitIdentity{}, domain.NewProviderError(ProviderName,
			errors.New("token belongs to a different github user than providers.github.login"))
	}
	id := GitIdentity{Name: p.cfg.GitName, Email: p.cfg.GitEmail}
	if id.Name == "" {
		id.Name = p.cfg.Login
	}
	if id.Email == "" {
		id.Email = "<id>+<login>@users.noreply.github.com"
	}
	id.Email = strings.NewReplacer("<id>", strconv.FormatInt(u.ID, 10), "<login>", p.cfg.Login).Replace(id.Email)
	return id, nil
}
