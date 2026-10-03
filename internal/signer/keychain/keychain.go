// Package keychain implements domain.Signer over a macOS Keychain / Secure Enclave key behind the Backend
// interface. The portable logic here compiles everywhere; the hardware opener
// lives in open_darwin.go (build tag darwin) with a stub in open_other.go that returns
// domain.ErrConfig on every other platform.
package keychain

import (
	"context"
	"crypto"
	"crypto/x509"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/signer/kms"
)

// Backend is the narrow hardware seam. SignDigest receives a SHA-256 digest
// and returns a PKCS#1 v1.5 signature for RS256 or an ASN.1 DER ECDSA
// signature for ES256 (converted to JOSE R||S here, ASSUMPTION(A-10)).
// The private key never leaves the device.
type Backend interface {
	Public() (crypto.PublicKey, error)
	SignDigest(ctx context.Context, alg string, digest []byte) ([]byte, error)
}

// Signer implements domain.Signer.
type Signer struct{ *kms.Signer }

var _ domain.Signer = (*Signer)(nil)

// New wraps b. kid is the key id registered in Okta.
func New(b Backend, kid string) (*Signer, error) {
	if b == nil {
		return nil, domain.NewConfigError("signer.keychain.backend", "missing backend")
	}
	k, err := kms.New(adapter{b}, "keychain", kid)
	if err != nil {
		return nil, err
	}
	return &Signer{k}, nil
}

type adapter struct{ b Backend }

func (a adapter) SignDigest(ctx context.Context, _ string, digest []byte, spec string) ([]byte, error) {
	alg := "RS256"
	if spec == kms.AlgSpecECDSA {
		alg = "ES256"
	}
	return a.b.SignDigest(ctx, alg, digest)
}

func (a adapter) PublicKeyDER(context.Context, string) ([]byte, error) {
	pub, err := a.b.Public()
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(pub)
}
