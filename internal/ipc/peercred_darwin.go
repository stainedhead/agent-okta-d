//go:build darwin

package ipc

import (
	"errors"
	"net"
	"syscall"
	"unsafe"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

const (
	solLocal       = 0 // SOL_LOCAL
	localPeerCred  = 1 // LOCAL_PEERCRED
	localPeerPID   = 2 // LOCAL_PEERPID
	xucredVersion  = 0 // XUCRED_VERSION
	xucredMaxGroup = 16
)

// xucred mirrors struct xucred from <sys/ucred.h>.
type xucred struct {
	Version uint32
	UID     uint32
	NGroups int16
	_       int16 // padding to match the C layout
	Groups  [xucredMaxGroup]uint32
}

// PeerCred reads LOCAL_PEERCRED and LOCAL_PEERPID. The first group in the
// xucred is the peer's effective gid; the rest are supplementary groups.
type PeerCred struct{}

// NewPeerCred returns the platform peer-credential reader.
func NewPeerCred() domain.PeerCredReader { return PeerCred{} }

func getsockopt(fd uintptr, level, opt int, p unsafe.Pointer, n *uint32) error {
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, uintptr(level), uintptr(opt), uintptr(p), uintptr(unsafe.Pointer(n)), 0)
	if e != 0 {
		return e
	}
	return nil
}

// Read implements domain.PeerCredReader.
func (PeerCred) Read(conn net.Conn) (domain.CallerInfo, error) {
	var (
		cred xucred
		pid  int32
		serr error
	)
	if err := rawControl(conn, func(fd uintptr) {
		n := uint32(unsafe.Sizeof(cred))
		if serr = getsockopt(fd, solLocal, localPeerCred, unsafe.Pointer(&cred), &n); serr != nil {
			return
		}
		m := uint32(unsafe.Sizeof(pid))
		serr = getsockopt(fd, solLocal, localPeerPID, unsafe.Pointer(&pid), &m)
	}); err != nil {
		return domain.CallerInfo{}, err
	}
	if serr != nil {
		return domain.CallerInfo{}, serr
	}
	return callerFromXucred(cred, int(pid))
}

func callerFromXucred(cred xucred, pid int) (domain.CallerInfo, error) {
	if cred.Version != xucredVersion {
		return domain.CallerInfo{}, errors.New("unexpected xucred version")
	}
	if cred.NGroups < 1 || int(cred.NGroups) > xucredMaxGroup {
		return domain.CallerInfo{}, errors.New("peer reported no groups")
	}
	info := domain.CallerInfo{UID: int(cred.UID), GID: int(cred.Groups[0]), PID: pid}
	for _, g := range cred.Groups[:cred.NGroups] {
		info.Groups = append(info.Groups, int(g))
	}
	return info, nil
}
