//go:build unix

package ipc

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// FR-R04: the socket is created with the target mode even under umask 000.
func TestListenUnixModeUnderPermissiveUmask(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "ipc")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	var seen os.FileMode
	bindHook = func(p string) {
		fi, err := os.Stat(p)
		if err != nil {
			t.Error(err)
			return
		}
		seen = fi.Mode().Perm()
	}
	defer func() { bindHook = nil }()

	p := filepath.Join(dir, "s")
	ln, err := ListenUnix(p, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if seen != 0o640 {
		t.Errorf("mode right after bind (before chmod) = %v, want 0640", seen)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
		t.Errorf("final mode %v", fi.Mode().Perm())
	}
	if prev := syscall.Umask(0); prev != 0 {
		t.Errorf("process umask not restored: %o", prev)
	}
}

func TestCheckSocketDir(t *testing.T) {
	root := t.TempDir()
	mk := func(name string, mode os.FileMode) string {
		d := filepath.Join(root, name)
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, mode); err != nil {
			t.Fatal(err)
		}
		return d
	}
	euid := os.Geteuid()
	for _, c := range []struct {
		name string
		dir  string
		euid int
		ok   bool
	}{
		{"private", mk("a", 0o700), euid, true},
		{"group-readable", mk("b", 0o750), euid, true},
		{"world-readable", mk("c", 0o755), euid, false},
		{"world-writable", mk("d", 0o770|0o002), euid, false},
		{"foreign owner", mk("e", 0o750), euid + 1, false},
		{"missing", filepath.Join(root, "nope"), euid, false},
	} {
		err := checkSocketDir(c.dir, c.euid)
		if c.ok != (err == nil) {
			t.Errorf("%s: err=%v", c.name, err)
		}
		if err != nil && c.name != "missing" && !errors.Is(err, domain.ErrPolicy) {
			t.Errorf("%s: want ErrPolicy, got %v", c.name, err)
		}
	}
	f := filepath.Join(root, "file")
	_ = os.WriteFile(f, nil, 0o600)
	if err := CheckSocketDir(f); !errors.Is(err, domain.ErrPolicy) {
		t.Errorf("not a directory: %v", err)
	}
	if err := CheckSocketDir(mk("ok", 0o700)); err != nil {
		t.Errorf("public wrapper: %v", err)
	}
}
