//go:build !linux

package tpm

import "github.com/stainedhead/agent-okta-d/internal/domain"

// Supported reports whether this build can reach the Linux TPM 2.0.
const Supported = false

// Open always fails on this platform with domain.ErrConfig.
func Open(string) (Backend, error) {
	return nil, domain.NewConfigError("signer.tpm", "unsupported on this platform: Linux TPM 2.0 signer requires linux")
}
