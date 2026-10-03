//go:build linux

package tpm

import "github.com/stainedhead/agent-okta-d/internal/domain"

// Supported reports whether this build can reach the Linux TPM 2.0.
const Supported = true

// Open returns the hardware Backend for the key named ref.
// ASSUMPTION(A-12): the real implementation needs cgo / vendor tooling and
// hardware, which cannot be verified in PR CI; until it lands this returns
// domain.ErrConfig so a CGO_ENABLED=0 build still compiles and fails clearly.
func Open(ref string) (Backend, error) {
	return nil, domain.NewConfigError("signer.tpm", "Linux TPM 2.0 backend not implemented in this build (ref "+ref+")")
}
