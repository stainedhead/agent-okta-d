package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestBinarySmoke builds the real binary and checks the exit codes of the
// commands that need no daemon and no network (FR-R10).
func TestBinarySmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "agent-okta-d")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil { //nolint:gosec // fixed arguments
		t.Fatalf("build: %v\n%s", err, out)
	}
	run := func(args ...string) (int, string) {
		cmd := exec.Command(bin, args...) //nolint:gosec // test binary built above
		cmd.Env = append(os.Environ(), "AGENT_OKTA_D_SOCKET="+filepath.Join(t.TempDir(), "none.sock"))
		out, err := cmd.CombinedOutput()
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), string(out)
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0, string(out)
	}
	if code, out := run("version"); code != 0 || !strings.Contains(out, "agent-okta-d") {
		t.Fatalf("version: %d %q", code, out)
	}
	if code, _ := run(); code == 0 {
		t.Fatal("no arguments must be a usage error")
	}
}
