package ipc

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"time"
)

// ListenUnix listens on a unix socket at path with the given file mode. A
// stale socket file left by a crashed daemon is replaced; a live one, or any
// other kind of file, is an error. The socket is chmod-ed to mode right after bind.
func ListenUnix(path string, mode fs.FileMode) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("ipc: %s exists and is not a socket", path)
		}
		if c, derr := net.DialTimeout("unix", path, time.Second); derr == nil {
			_ = c.Close()
			return nil, fmt.Errorf("ipc: %s is already in use", path)
		}
		if rerr := os.Remove(path); rerr != nil {
			return nil, fmt.Errorf("ipc: remove stale socket: %w", rerr)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("ipc: chmod socket: %w", err)
	}
	return ln, nil
}
