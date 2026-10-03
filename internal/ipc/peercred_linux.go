//go:build linux

package ipc

import (
	"net"
	"syscall"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// PeerCred reads SO_PEERCRED. Linux reports uid, gid and pid, but not the
// peer's supplementary groups; those are read from /proc/<pid>/status (see
// groupsOf). When /proc is unreadable only the primary gid is checked.
type PeerCred struct{}

// NewPeerCred returns the platform peer-credential reader.
func NewPeerCred() domain.PeerCredReader { return PeerCred{} }

// Read implements domain.PeerCredReader.
func (PeerCred) Read(conn net.Conn) (domain.CallerInfo, error) {
	var (
		ucred *syscall.Ucred
		serr  error
	)
	if err := rawControl(conn, func(fd uintptr) {
		ucred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return domain.CallerInfo{}, err
	}
	if serr != nil {
		return domain.CallerInfo{}, serr
	}
	pid := int(ucred.Pid)
	return domain.CallerInfo{UID: int(ucred.Uid), GID: int(ucred.Gid), PID: pid, Exe: exeOf(pid), Groups: groupsOf(pid)}, nil
}
