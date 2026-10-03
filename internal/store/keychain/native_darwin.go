//go:build darwin && cgo

package keychain

import "github.com/stainedhead/agent-okta-d/internal/domain"

// NewNative would open the macOS Keychain generic-password items for service.
// ASSUMPTION(A-12): the Security.framework (cgo) backend is deferred; until it
// lands this build fails closed with ErrConfig, exactly like the stub.
func NewNative(service string) (*Store, error) {
	return nil, domain.NewConfigError("store.keychain", "native keychain backend not implemented yet")
}
