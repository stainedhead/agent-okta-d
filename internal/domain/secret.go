package domain

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
)

// Redacted is the only text a SecretString ever renders as.
const Redacted = "[redacted]"

// SecretString holds a token, assertion, refresh token or other secret value.
// Every formatting, encoding and logging path renders Redacted; the value is
// obtained only through the explicit Reveal call. The zero value is an empty
// secret. The wrapped field is unexported so a SecretString cannot be
// converted to string by accident.
//
// Limitation: fmt cannot call methods on a SecretString held in an unexported
// struct field, so never store one there if the struct may be printed.
type SecretString struct{ v string }

// NewSecret wraps v.
func NewSecret(v string) SecretString { return SecretString{v: v} }

// Reveal returns the raw value. Call it only at the point of use (writing a
// sink, building an HTTP header) and never log the result.
func (s SecretString) Reveal() string { return s.v }

// Len reports the byte length of the secret.
func (s SecretString) Len() int { return len(s.v) }

// IsZero reports whether the secret is empty.
func (s SecretString) IsZero() bool { return s.v == "" }

// Equal compares two secrets in constant time.
func (s SecretString) Equal(o SecretString) bool {
	return subtle.ConstantTimeCompare([]byte(s.v), []byte(o.v)) == 1
}

// String implements fmt.Stringer.
func (SecretString) String() string { return Redacted }

// GoString implements fmt.GoStringer (the %#v verb).
func (SecretString) GoString() string { return "domain.SecretString{" + Redacted + "}" }

// Format implements fmt.Formatter so that no verb can print the value.
func (s SecretString) Format(f fmt.State, verb rune) {
	if verb == 'T' {
		_, _ = f.Write([]byte("domain.SecretString"))
		return
	}
	if verb == 'v' && f.Flag('#') {
		_, _ = f.Write([]byte(s.GoString()))
		return
	}
	_, _ = f.Write([]byte(Redacted))
}

// MarshalJSON implements json.Marshaler.
func (SecretString) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// MarshalText implements encoding.TextMarshaler.
func (SecretString) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// LogValue implements slog.LogValuer.
func (SecretString) LogValue() slog.Value { return slog.StringValue(Redacted) }
