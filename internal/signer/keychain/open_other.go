//go:build !darwin

package keychain

import "github.com/stainedhead/agent-okta-d/internal/domain"

// Supported reports whether this build can reach the macOS Keychain / Secure Enclave.
const Supported = false

// Open always fails on this platform with domain.ErrConfig.
func Open(string) (Backend, error) {
	return nil, domain.NewConfigError("signer.keychain", "unsupported on this platform: macOS Keychain / Secure Enclave signer requires darwin")
}
