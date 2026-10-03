package domain

import (
	"fmt"
	"time"
)

// Kind identifies the shape of a credential value.
type Kind string

// Credential kinds (PRD section 9).
const (
	KindBearer         Kind = "bearer"
	KindAWSWebIdentity Kind = "aws-web-identity"
	KindStaticSecret   Kind = "static-secret"
)

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	return k == KindBearer || k == KindAWSWebIdentity || k == KindStaticSecret
}

// Well-known Credential.Meta keys. Meta never holds secrets.
const (
	MetaAudience = "audience"
	MetaScope    = "scope"
	MetaKID      = "kid"
	MetaLogin    = "login"
	MetaJTI      = "jti"
)

// Credential is a short-lived credential produced by a Provider. Every
// credential must carry a non-zero IssuedAt and an ExpiresAt after it, also
// kind static-secret: a provider with a long-lived secret sets ExpiresAt to
// its re-fetch horizon (the cache uses it to schedule refresh).
type Credential struct {
	Kind      Kind
	Value     SecretString
	IssuedAt  time.Time
	ExpiresAt time.Time
	Meta      map[string]string // audience, scope, kid; never secrets
}

// Validate enforces the edge-case rules of the spec (section 10b): an empty
// value, unknown kind, missing expiry or zero/negative TTL is ErrProvider and
// the credential must never be cached or served. The error never contains the
// value.
func (c Credential) Validate() error {
	switch {
	case !c.Kind.Valid():
		return Wrap(ErrProvider, fmt.Errorf("unknown credential kind %q", string(c.Kind)))
	case c.Value.IsZero():
		return Wrap(ErrProvider, fmt.Errorf("empty credential value"))
	case c.IssuedAt.IsZero():
		return Wrap(ErrProvider, fmt.Errorf("missing issued_at"))
	case c.ExpiresAt.IsZero():
		return Wrap(ErrProvider, fmt.Errorf("missing expires_at"))
	case !c.ExpiresAt.After(c.IssuedAt):
		return Wrap(ErrProvider, fmt.Errorf("non-positive credential lifetime"))
	}
	return nil
}

// TTL is the full lifetime, ExpiresAt minus IssuedAt.
func (c Credential) TTL() time.Duration { return c.ExpiresAt.Sub(c.IssuedAt) }

// Remaining is the time until expiry at now, never negative.
func (c Credential) Remaining(now time.Time) time.Duration {
	return max(c.ExpiresAt.Sub(now), 0)
}

// Expired reports whether the credential is at or past ExpiresAt.
func (c Credential) Expired(now time.Time) bool { return !now.Before(c.ExpiresAt) }

// Elapsed is the fraction of the lifetime used at now, clamped to [0, 1]. A
// credential without a positive TTL counts as fully elapsed.
func (c Credential) Elapsed(now time.Time) float64 {
	ttl := c.TTL()
	if ttl <= 0 {
		return 1
	}
	return min(max(float64(now.Sub(c.IssuedAt))/float64(ttl), 0), 1)
}

// Audience returns Meta["audience"] or "".
func (c Credential) Audience() string { return c.Meta[MetaAudience] }

// Key addresses a cache entry (FR-3).
type Key struct {
	Provider string
	Audience string
	Scope    string
}

// String renders provider|audience|scope.
func (k Key) String() string { return k.Provider + "|" + k.Audience + "|" + k.Scope }

// CacheEntry is the cache's record for a Key.
type CacheEntry struct {
	Key         Key
	Credential  Credential
	State       State
	LastError   error
	NextRefresh time.Time
}

// LastErrorClass returns the audit class of LastError ("" when none).
func (e CacheEntry) LastErrorClass() string { return ErrorClass(e.LastError) }
