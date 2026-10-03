//go:build !unix

package ipc

import (
	"net"
	"os"
)

func listenWithMode(path string, _ os.FileMode) (net.Listener, error) {
	return net.Listen("unix", path)
}

// CheckSocketDir is a no-op where unix permissions do not apply.
func CheckSocketDir(string) error { return nil }
