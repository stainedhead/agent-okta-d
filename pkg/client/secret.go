package client

import (
	"encoding/json"
	"fmt"
	"log/slog"
)

// Redacted is the only text a Secret ever renders as.
const Redacted = "[redacted]"

// Secret holds an access token. Every formatting, encoding and logging path
// renders Redacted; the raw value is available only through Reveal. The zero
// value is an empty secret.
type Secret struct{ v string }

// NewSecret wraps v.
func NewSecret(v string) Secret { return Secret{v: v} }

// Reveal returns the raw value. Call it only at the point of use (building an
// Authorization header, writing a file) and never log the result.
func (s Secret) Reveal() string { return s.v }

// IsZero reports whether the secret is empty.
func (s Secret) IsZero() bool { return s.v == "" }

// String implements fmt.Stringer and returns Redacted.
func (s Secret) String() string { return Redacted }

// GoString implements fmt.GoStringer and returns Redacted.
func (s Secret) GoString() string { return Redacted }

// Format implements fmt.Formatter; every verb prints Redacted.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(Redacted)) }

// MarshalJSON encodes Redacted, never the value.
func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal(Redacted) }

// MarshalText encodes Redacted, never the value.
func (s Secret) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// UnmarshalJSON decodes a JSON string into the secret.
func (s *Secret) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	s.v = v
	return nil
}

// LogValue implements slog.LogValuer and returns Redacted.
func (s Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }
