package github

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

func TestGitConfigSnippet(t *testing.T) {
	got, err := GitConfigSnippet("/usr/local/bin/agent-okta-d", "https://github.com", GitIdentity{Name: "sdlc", Email: "7+agent@users.noreply.github.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := "[credential \"https://github.com\"]\n\thelper =\n\thelper = !'/usr/local/bin/agent-okta-d' credential-helper github\n[user]\n\tname = sdlc\n\temail = 7+agent@users.noreply.github.com\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestGitConfigSnippetNoIdentity(t *testing.T) {
	got, err := GitConfigSnippet("agent-okta-d", "https://ghe.example.com", GitIdentity{})
	if err != nil || strings.Contains(got, "[user]") || !strings.Contains(got, `[credential "https://ghe.example.com"]`) {
		t.Fatalf("%q %v", got, err)
	}
}

func TestGitConfigSnippetRejectsBadInput(t *testing.T) {
	for _, c := range []struct {
		bin, base string
		id        GitIdentity
	}{
		{"", "https://github.com", GitIdentity{}},
		{"a", "", GitIdentity{}},
		{"a", "https://github.com\n[x]", GitIdentity{}},
		{"a\nb", "https://github.com", GitIdentity{}},
		{"a", "https://github.com", GitIdentity{Name: "x\ny = z"}},
		{"a", "https://github.com", GitIdentity{Email: "e\n"}},
	} {
		if _, err := GitConfigSnippet(c.bin, c.base, c.id); !errors.Is(err, domain.ErrConfig) {
			t.Errorf("%+v: got %v", c, err)
		}
	}
}

func TestGitConfigCommands(t *testing.T) {
	cmds := GitConfigCommands("/bin/aod", "https://github.com", GitIdentity{Name: "n", Email: "e@x"})
	flat := make([]string, 0, len(cmds))
	for _, c := range cmds {
		flat = append(flat, strings.Join(c, " "))
	}
	want := []string{
		"git config --system --replace-all credential.https://github.com.helper ",
		"git config --system --add credential.https://github.com.helper !'/bin/aod' credential-helper github",
		"git config --system user.name n",
		"git config --system user.email e@x",
	}
	if strings.Join(flat, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s", strings.Join(flat, "\n"))
	}
}

func TestResolveGitIdentity(t *testing.T) {
	f := newFixture(t, func(c *Config) {
		c.GitName = "sdlc-reviewer-01"
		c.GitEmail = "<id>+<login>@users.noreply.github.com"
	}, nil)
	// ASSUMPTION(A-05): the noreply form is unconfirmed for EMU/GHE.com.
	id, err := f.p.ResolveGitIdentity(context.Background(), domain.NewSecret("t"))
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "sdlc-reviewer-01" || id.Email != "7+agent-x_acme@users.noreply.github.com" {
		t.Fatalf("%+v", id)
	}
}

func TestResolveGitIdentityDefaultsAndLiteral(t *testing.T) {
	f := newFixture(t, nil, nil)
	id, err := f.p.ResolveGitIdentity(context.Background(), domain.NewSecret("t"))
	if err != nil || id.Name != "agent-x_acme" || id.Email != "7+agent-x_acme@users.noreply.github.com" {
		t.Fatalf("%+v %v", id, err)
	}
	f = newFixture(t, func(c *Config) { c.GitEmail = "agent@corp.example" }, nil)
	id, _ = f.p.ResolveGitIdentity(context.Background(), domain.NewSecret("t"))
	if id.Email != "agent@corp.example" {
		t.Fatalf("%+v", id)
	}
}

func TestResolveGitIdentityErrors(t *testing.T) {
	f := newFixture(t, nil, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) })
	if _, err := f.p.ResolveGitIdentity(context.Background(), domain.NewSecret("t")); !errors.Is(err, domain.ErrReauthRequired) {
		t.Fatalf("got %v", err)
	}
	f = newFixture(t, func(c *Config) { c.Login = "someone-else" }, nil)
	if _, err := f.p.ResolveGitIdentity(context.Background(), domain.NewSecret("t")); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("login mismatch: %v", err)
	}
}
