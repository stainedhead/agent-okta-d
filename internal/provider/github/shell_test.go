package github

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

func TestShellQuote(t *testing.T) {
	cases := map[string]string{"abc": "'abc'", "a b": "'a b'", "it's": `'it'\''s'`, "": "''", "$(x)": "'$(x)'"}
	for in, want := range cases {
		if got := ShellQuote(in); got != want {
			t.Errorf("%q -> %q want %q", in, got, want)
		}
	}
}

func TestEnvLines(t *testing.T) {
	got, err := EnvLines(domain.NewSecret("ghp_a'b"), "https://api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != "export GH_TOKEN='ghp_a'\\''b'\n" {
		t.Fatalf("%q", got)
	}
	got, _ = EnvLines(domain.NewSecret("t"), "https://ghe.example.com/api/v3")
	if got != "export GH_ENTERPRISE_TOKEN='t'\nexport GH_HOST='ghe.example.com'\n" {
		t.Fatalf("ghes: %q", got)
	}
	if _, err := EnvLines(domain.NewSecret(""), ""); err == nil {
		t.Fatal("empty token must error")
	}
	if _, err := EnvLines(domain.NewSecret("a\nb"), ""); err == nil {
		t.Fatal("newline must error")
	}
}

func TestShimScriptContent(t *testing.T) {
	s, err := ShimScript("/usr/local/bin/agent-okta-d", "/usr/bin/gh")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"#!/bin/sh", "'/usr/local/bin/agent-okta-d' token github --format raw", "export GH_TOKEN", "exec '/usr/bin/gh' \"$@\""} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "auth login") {
		t.Fatal("shim must not use gh auth login")
	}
	for _, bad := range [][2]string{{"", "/gh"}, {"/a", ""}, {"/a\nb", "/gh"}} {
		if _, err := ShimScript(bad[0], bad[1]); !errors.Is(err, domain.ErrConfig) {
			t.Errorf("%v: got %v", bad, err)
		}
	}
}

// TestShimScriptRuns executes the generated shim with a fake daemon binary and
// a fake gh to prove the token reaches gh's environment and args pass through.
func TestShimScriptRuns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix shell")
	}
	dir := t.TempDir()
	daemon := filepath.Join(dir, "agent-okta-d")
	gh := filepath.Join(dir, "gh it's")
	write := func(p, body string) {
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil { //nolint:gosec // test script
			t.Fatal(err)
		}
	}
	write(daemon, "#!/bin/sh\n[ \"$1 $2 $3 $4\" = \"token github --format raw\" ] || exit 9\nprintf 'ghp_fromdaemon'\n")
	write(gh, "#!/bin/sh\nprintf '%s|%s|%s' \"$GH_TOKEN\" \"$1\" \"$2\"\n")
	script, err := ShimScript(daemon, gh)
	if err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(dir, "shim")
	write(shim, script)
	out, err := exec.CommandContext(context.Background(), shim, "pr", "create").Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "ghp_fromdaemon|pr|create" {
		t.Fatalf("out=%q", out)
	}
	// daemon failure must stop the shim before gh runs
	write(daemon, "#!/bin/sh\nexit 3\n")
	out, err = exec.CommandContext(context.Background(), shim, "pr").CombinedOutput()
	if err == nil || strings.Contains(string(out), "|") {
		t.Fatalf("shim should fail closed: %v %q", err, out)
	}
}
