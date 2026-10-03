package ipc

import (
	"errors"
	"net"
)

// ErrPeerCredUnsupported is returned by the platform reader on platforms
// without peer-credential support. Callers treat it as deny.
var ErrPeerCredUnsupported = errors.New("peer credentials unsupported on this platform")

// unixConn extracts the underlying unix connection.
func unixConn(conn net.Conn) (*net.UnixConn, error) {
	if lc, ok := conn.(*limitConn); ok {
		conn = lc.Conn // see limit.go
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errors.New("not a unix connection")
	}
	return uc, nil
}

// rawControl runs f on the connection's file descriptor.
func rawControl(conn net.Conn, f func(fd uintptr)) error {
	uc, err := unixConn(conn)
	if err != nil {
		return err
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	return rc.Control(f)
}
