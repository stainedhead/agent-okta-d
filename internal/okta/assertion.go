package okta

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// Algorithms accepted for client assertions.
const (
	AlgRS256 = "RS256"
	// AlgES256 is ASSUMPTION(A-01): Okta accepting ES256 client assertions is
	// unconfirmed (PRD 6.3). RS256 is the default.
	AlgES256 = "ES256"
)

// DefaultAssertionTTL is the lifetime of a client assertion (PRD 6.3: now + 60 s).
const DefaultAssertionTTL = 60 * time.Second

// AssertionBuilder builds and signs client assertion JWTs.
type AssertionBuilder struct {
	// ClientID is used for both iss and sub.
	ClientID string
	Signer   domain.Signer
	// Alg is RS256 (default) or ES256 (ASSUMPTION(A-01)).
	Alg   string
	Clock domain.Clock
	// TTL defaults to DefaultAssertionTTL.
	TTL time.Duration
	// Rand is the entropy source for jti; defaults to crypto/rand.
	Rand io.Reader

	mu  sync.Mutex
	kid string // cached from the first Sign result when the signer has no KID()
}

// Assertion is a signed client assertion and its audit-relevant metadata.
type Assertion struct {
	JWT       domain.SecretString
	JTI       string
	KID       string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Jti string `json:"jti"`
}

func (b *AssertionBuilder) validate() (alg string, ttl time.Duration, err error) {
	switch {
	case b.ClientID == "":
		return "", 0, domain.NewConfigError("okta.client_id", "client id is required")
	case b.Signer == nil:
		return "", 0, domain.NewConfigError("okta.signer", "signer is required")
	case b.Clock == nil:
		return "", 0, domain.NewConfigError("okta.clock", "clock is required")
	}
	alg = b.Alg
	if alg == "" {
		alg = AlgRS256
	}
	if alg != AlgRS256 && alg != AlgES256 {
		return "", 0, domain.NewConfigError("okta.signer.alg", "unsupported algorithm "+alg)
	}
	ttl = b.TTL
	if ttl == 0 {
		ttl = DefaultAssertionTTL
	}
	if ttl < 0 || ttl > time.Hour { // Okta allows up to 60 min (PRD 6.3)
		return "", 0, domain.NewConfigError("okta.assertion_ttl", "must be between 0 and 1h")
	}
	return alg, ttl, nil
}

// Build creates a fresh assertion for the token endpoint audience aud
// (the full token endpoint URL of the authorization server).
func (b *AssertionBuilder) Build(ctx context.Context, aud string) (Assertion, error) {
	alg, ttl, err := b.validate()
	if err != nil {
		return Assertion{}, err
	}
	if aud == "" {
		return Assertion{}, domain.NewConfigError("okta.aud", "assertion audience is required")
	}
	jti, err := b.newJTI()
	if err != nil {
		return Assertion{}, domain.Wrap(domain.ErrProvider, errors.New("jti generation failed"))
	}
	now := b.Clock.Now()
	iat, exp := now.Truncate(time.Second), now.Truncate(time.Second).Add(ttl)

	kid, err := b.keyID(ctx, alg)
	if err != nil {
		return Assertion{}, err
	}
	hdr, _ := json.Marshal(jwtHeader{Alg: alg, Kid: kid, Typ: "JWT"})
	claims, _ := json.Marshal(jwtClaims{
		Iss: b.ClientID, Sub: b.ClientID, Aud: aud,
		Iat: iat.Unix(), Exp: exp.Unix(), Jti: jti,
	})
	input := b64(hdr) + "." + b64(claims)
	sig, sigKID, err := b.Signer.Sign(ctx, alg, []byte(input))
	if err != nil {
		return Assertion{}, classifySignerErr(err)
	}
	if sigKID != kid {
		return Assertion{}, domain.Wrap(domain.ErrProvider, errors.New("signer key id changed while signing"))
	}
	return Assertion{
		JWT:       domain.NewSecret(input + "." + b64(sig)),
		JTI:       jti,
		KID:       kid,
		IssuedAt:  iat,
		ExpiresAt: exp,
	}, nil
}

func (b *AssertionBuilder) newJTI() (string, error) {
	r := b.Rand
	if r == nil {
		r = rand.Reader
	}
	buf := make([]byte, 16)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// keyID returns the registered key id. Signers that expose KID() are asked
// directly; otherwise the id comes from one probe Sign call over a fixed,
// non-secret input and is cached, so the usual path costs a single signing
// operation per assertion (important for KMS billing and latency).
func (b *AssertionBuilder) keyID(ctx context.Context, alg string) (string, error) {
	if k, ok := b.Signer.(interface{ KID() string }); ok && k.KID() != "" {
		return k.KID(), nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.kid != "" {
		return b.kid, nil
	}
	_, kid, err := b.Signer.Sign(ctx, alg, []byte("kid-probe"))
	if err != nil {
		return "", classifySignerErr(err)
	}
	if kid == "" {
		return "", domain.NewConfigError("okta.signer.kid", "signer returned an empty key id")
	}
	b.kid = kid
	return kid, nil
}

// classifySignerErr keeps errors already in the domain taxonomy and treats any
// other signer failure as a provider error. The cause text is dropped for
// unclassified errors so nothing a backend echoes can reach logs.
func classifySignerErr(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if domain.ErrorClass(err) != "unknown" {
		return fmt.Errorf("sign client assertion: %w", err)
	}
	return domain.Wrap(domain.ErrProvider, errors.New("sign client assertion failed"))
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
