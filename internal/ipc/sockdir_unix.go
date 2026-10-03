//go:build unix

package ipc

import (
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

var umaskMu sync.Mutex

// bindHook runs right after bind and before chmod (tests only).
var bindHook func(path string)

// listenWithMode binds a unix socket whose creation mode is already mode, by
// narrowing the process umask for the duration of the bind, so there is no
// window in which the socket is wider than mode.
func listenWithMode(path string, mode os.FileMode) (net.Listener, error) {
	umaskMu.Lock()
	old := syscall.Umask(int(^mode & 0o777))
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	umaskMu.Unlock()
	if err == nil && bindHook != nil {
		bindHook(path)
	}
	return ln, err
}

// CheckSocketDir fails with ErrPolicy unless dir is a directory owned by the
// effective user that grants nothing to "other" (FR-R04).
func CheckSocketDir(dir string) error { return checkSocketDir(dir, os.Geteuid()) }

func checkSocketDir(dir string, euid int) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return domain.Wrap(domain.ErrPolicy, fmt.Errorf("socket directory %s is not a directory", dir))
	}
	if fi.Mode().Perm()&0o007 != 0 {
		return domain.Wrap(domain.ErrPolicy, fmt.Errorf("socket directory %s is accessible to other users (mode %04o); chmod o-rwx", dir, fi.Mode().Perm()))
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != euid {
		return domain.Wrap(domain.ErrPolicy, fmt.Errorf("socket directory %s is owned by uid %d, not the daemon user %d", dir, st.Uid, euid))
	}
	return nil
}
