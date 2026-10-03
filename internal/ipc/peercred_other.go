//go:build !linux && !darwin

package ipc

import (
	"net"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// PeerCred denies every connection: there is no peer-credential support here.
// Tests use domaintest.FakePeerCred instead.
type PeerCred struct{}

// NewPeerCred returns the platform peer-credential reader.
func NewPeerCred() domain.PeerCredReader { return PeerCred{} }

// Read implements domain.PeerCredReader.
func (PeerCred) Read(net.Conn) (domain.CallerInfo, error) {
	return domain.CallerInfo{}, ErrPeerCredUnsupported
}
