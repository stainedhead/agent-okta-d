//go:build !(darwin && cgo)

package keychain

import "github.com/stainedhead/agent-okta-d/internal/domain"

// NewNative is unavailable on this build. ASSUMPTION(A-12): the macOS
// Keychain backend needs cgo, so non-darwin and non-cgo builds get this stub.
func NewNative(service string) (*Store, error) {
	return nil, domain.NewConfigError("store.keychain", "native keychain is not available on this build")
}
