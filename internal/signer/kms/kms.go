package kms

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// KMS signing algorithm names (AWS SigningAlgorithmSpec values).
const (
	AlgSpecRSA   = "RSASSA_PKCS1_V1_5_SHA_256"
	AlgSpecECDSA = "ECDSA_SHA_256"
)

// KMSAPI is the narrow slice of a KMS client the signer needs. An adapter over
// the AWS SDK lives outside this package; tests use a fake.
type KMSAPI interface {
	// SignDigest signs a SHA-256 digest (MessageType DIGEST) with keyID using
	// signingAlgorithm and returns KMS's raw signature (DER for ECDSA).
	SignDigest(ctx context.Context, keyID string, digest []byte, signingAlgorithm string) ([]byte, error)
	// PublicKeyDER returns the key's public key as DER SubjectPublicKeyInfo.
	PublicKeyDER(ctx context.Context, keyID string) ([]byte, error)
}

// Signer implements domain.Signer over KMSAPI.
type Signer struct {
	api   KMSAPI
	keyID string
	kid   string

	mu  sync.Mutex
	pub crypto.PublicKey
}

var _ domain.Signer = (*Signer)(nil)

// New builds a KMS signer. keyID is the KMS key id/ARN; kid is the key id
// registered in Okta.
func New(api KMSAPI, keyID, kid string) (*Signer, error) {
	if api == nil {
		return nil, domain.NewConfigError("signer.kms.api", "missing KMS client")
	}
	if keyID == "" {
		return nil, domain.NewConfigError("signer.key_id", "required")
	}
	return &Signer{api: api, keyID: keyID, kid: kid}, nil
}

func specFor(alg string) (string, error) {
	switch alg {
	case "RS256":
		return AlgSpecRSA, nil
	case "ES256": // ASSUMPTION(A-01): Okta accepts ES256 client assertions.
		return AlgSpecECDSA, nil
	}
	return "", domain.NewConfigError("alg", "unsupported algorithm "+alg)
}

// Sign implements domain.Signer. ES256 output is JOSE raw R||S.
func (s *Signer) Sign(ctx context.Context, alg string, signingInput []byte) ([]byte, string, error) {
	spec, err := specFor(alg)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(signingInput)
	raw, err := s.api.SignDigest(ctx, s.keyID, digest[:], spec)
	if err != nil {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		// ASSUMPTION(A-10): KMS failures are not definitive auth errors; treat as transient.
		return nil, "", domain.NewTransient(fmt.Errorf("kms sign: %w", err), 0)
	}
	if alg == "ES256" {
		raw, err = DERToJOSE(raw, es256CoordLen)
		if err != nil {
			return nil, "", domain.NewProviderError("kms", err)
		}
	}
	return raw, s.kid, nil
}

// Public implements domain.Signer; the key is fetched once and cached.
func (s *Signer) Public() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pub == nil {
		der, err := s.api.PublicKeyDER(context.Background(), s.keyID)
		if err != nil {
			return nil, domain.NewTransient(fmt.Errorf("kms get public key: %w", err), 0)
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, domain.NewProviderError("kms", fmt.Errorf("parse public key: %w", err))
		}
		s.pub = pub
	}
	return PublicJWK(s.pub, AlgFor(s.pub), s.kid)
}
