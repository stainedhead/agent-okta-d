package github

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// Mode selects how the agent's GitHub credential was created (PRD 7.2).
type Mode string

// Credential modes.
const (
	ModePAT         Mode = "pat"
	ModeOAuthDevice Mode = "oauth_device"
)

// Valid reports whether m is a known mode.
func (m Mode) Valid() bool { return m == ModePAT || m == ModeOAuthDevice }

const storedVersion = 1

// Stored is the document kept in the secret store under Config.SecretID. A
// value that does not start with '{' is read as a bare token (an operator who
// pasted a PAT straight into Secrets Manager), with no known expiry.
type Stored struct {
	Mode      Mode
	Token     string // plain text only inside this package boundary; never log it
	ExpiresAt time.Time
	Scope     string
}

type storedWire struct {
	V         int        `json:"v"`
	Mode      Mode       `json:"mode,omitempty"`
	Token     string     `json:"token"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Scope     string     `json:"scope,omitempty"`
}

// Encode renders s as the secret stored by `enroll`.
func (s Stored) Encode() (domain.SecretString, error) {
	if strings.TrimSpace(s.Token) == "" {
		return domain.SecretString{}, domain.Wrap(domain.ErrProvider, errors.New("empty github token"))
	}
	w := storedWire{V: storedVersion, Mode: s.Mode, Token: s.Token, Scope: s.Scope}
	if !s.ExpiresAt.IsZero() {
		t := s.ExpiresAt.UTC()
		w.ExpiresAt = &t
	}
	b, err := json.Marshal(w)
	if err != nil {
		return domain.SecretString{}, domain.Wrap(domain.ErrProvider, errors.New("encode github secret"))
	}
	return domain.NewSecret(string(b)), nil
}

// ParseStored decodes a stored secret. Errors never contain the value.
func ParseStored(v domain.SecretString) (Stored, error) {
	raw := strings.TrimSpace(v.Reveal())
	if raw == "" {
		return Stored{}, domain.Wrap(domain.ErrProvider, errors.New("stored github secret is empty"))
	}
	if !strings.HasPrefix(raw, "{") {
		return Stored{Token: raw}, nil
	}
	var w storedWire
	if err := json.Unmarshal([]byte(raw), &w); err != nil {
		return Stored{}, domain.Wrap(domain.ErrProvider, errors.New("stored github secret is not valid JSON"))
	}
	switch {
	case w.V != storedVersion:
		return Stored{}, domain.Wrap(domain.ErrProvider, fmt.Errorf("unsupported stored secret version %d", w.V))
	case strings.TrimSpace(w.Token) == "":
		return Stored{}, domain.Wrap(domain.ErrProvider, errors.New("stored github secret has no token"))
	case w.Mode != "" && !w.Mode.Valid():
		return Stored{}, domain.Wrap(domain.ErrProvider, fmt.Errorf("unknown stored mode %q", string(w.Mode)))
	}
	s := Stored{Mode: w.Mode, Token: strings.TrimSpace(w.Token), Scope: w.Scope}
	if w.ExpiresAt != nil {
		s.ExpiresAt = *w.ExpiresAt
	}
	return s, nil
}

// ExpiryState classifies a token expiry (GH-6).
type ExpiryState string

// Expiry states.
const (
	ExpiryUnknown ExpiryState = "unknown"
	ExpiryOK      ExpiryState = "ok"
	ExpiryWarn    ExpiryState = "warn"
	ExpiryExpired ExpiryState = "expired"
)

// DefaultExpiryWarningDays is the GH-6 warning horizon.
const DefaultExpiryWarningDays = 30

// ExpiryStatus classifies exp at now with a warning horizon of warnDays; a zero
// exp is ExpiryUnknown.
func ExpiryStatus(exp, now time.Time, warnDays int) ExpiryState {
	switch {
	case exp.IsZero():
		return ExpiryUnknown
	case !now.Before(exp):
		return ExpiryExpired
	case exp.Sub(now) <= time.Duration(warnDays)*24*time.Hour:
		return ExpiryWarn
	}
	return ExpiryOK
}
