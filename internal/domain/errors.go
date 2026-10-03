package domain

import (
	"errors"
	"time"
)

// Error taxonomy (PRD section 9). Match with errors.Is. Only ErrAuthDefinitive
// from Okta can lead to the revoked state; 5xx and network errors are always
// ErrTransient.
var (
	// ErrTransient marks network errors, timeouts, 429 and 5xx. Retry with backoff.
	ErrTransient = errors.New("transient error")
	// ErrAuthDefinitive marks a definitive Okta rejection (invalid_client,
	// unauthorized_client, invalid_grant, access_denied, client inactive).
	ErrAuthDefinitive = errors.New("definitive authentication error")
	// ErrConfig marks invalid or missing configuration. Exit code 78.
	ErrConfig = errors.New("configuration error")
	// ErrPolicy marks a local policy refusal (unknown caller gid, world-readable
	// key or sink, agent user running the daemon).
	ErrPolicy = errors.New("policy violation")
	// ErrProvider marks a provider-side failure that is neither transient nor an
	// auth rejection (malformed or empty credential, bad probe result).
	ErrProvider = errors.New("provider error")
	// ErrReauthRequired marks a user-credential provider (github, msgraph) whose
	// stored credential is expired, rejected or consented away. Never retried.
	ErrReauthRequired = errors.New("reauthentication required")
	// ErrRevoked marks the daemon revoked state. Exit code 77.
	ErrRevoked = errors.New("revoked")
	// ErrNotFound is returned by a SecretStore for a missing key.
	ErrNotFound = errors.New("not found")
	// ErrVersionConflict is returned by SecretStore.Put when the expected
	// version is stale (compare-and-set failed).
	ErrVersionConflict = errors.New("version conflict")
)

// ProviderError is ErrProvider with the provider name and cause attached.
type ProviderError struct {
	Provider string
	Cause    error
}

// NewProviderError builds a *ProviderError.
func NewProviderError(provider string, cause error) *ProviderError {
	return &ProviderError{Provider: provider, Cause: cause}
}

// Error implements error.
func (e *ProviderError) Error() string {
	if e.Cause == nil {
		return "provider " + e.Provider + ": failed"
	}
	return "provider " + e.Provider + ": " + e.Cause.Error()
}

// Unwrap exposes the cause.
func (e *ProviderError) Unwrap() error { return e.Cause }

// Is makes errors.Is(e, ErrProvider) true.
func (e *ProviderError) Is(target error) bool { return target == ErrProvider }

// TransientError is ErrTransient carrying an optional server retry hint
// (Retry-After or X-Rate-Limit-Reset).
type TransientError struct {
	Cause      error
	RetryAfter time.Duration
}

// NewTransient builds a *TransientError. A zero retryAfter means no hint.
func NewTransient(cause error, retryAfter time.Duration) *TransientError {
	return &TransientError{Cause: cause, RetryAfter: retryAfter}
}

// Error implements error.
func (e *TransientError) Error() string {
	if e.Cause == nil {
		return ErrTransient.Error()
	}
	return "transient error: " + e.Cause.Error()
}

// Unwrap exposes the cause.
func (e *TransientError) Unwrap() error { return e.Cause }

// Is makes errors.Is(e, ErrTransient) true.
func (e *TransientError) Is(target error) bool { return target == ErrTransient }

// RetryAfter extracts a server retry hint from err, if one is present.
func RetryAfter(err error) (time.Duration, bool) {
	var te *TransientError
	if errors.As(err, &te) && te.RetryAfter > 0 {
		return te.RetryAfter, true
	}
	return 0, false
}

// ConfigError is ErrConfig naming the offending field. It never carries the
// field's value, so secrets cannot leak through config errors.
type ConfigError struct {
	Field string
	Msg   string
}

// NewConfigError builds a *ConfigError.
func NewConfigError(field, msg string) *ConfigError { return &ConfigError{Field: field, Msg: msg} }

// Error implements error.
func (e *ConfigError) Error() string { return "config: " + e.Field + ": " + e.Msg }

// Is makes errors.Is(e, ErrConfig) true.
func (e *ConfigError) Is(target error) bool { return target == ErrConfig }

type wrapped struct {
	sentinel error
	cause    error
}

// Wrap attaches cause to a sentinel so both errors.Is(err, sentinel) and
// errors.Is(err, cause) hold.
func Wrap(sentinel, cause error) error {
	if cause == nil {
		return sentinel
	}
	return &wrapped{sentinel: sentinel, cause: cause}
}

func (w *wrapped) Error() string {
	s := w.sentinel.Error()
	switch w.sentinel {
	case ErrAuthDefinitive:
		s = "auth definitive"
	}
	return s + ": " + w.cause.Error()
}

func (w *wrapped) Unwrap() []error { return []error{w.sentinel, w.cause} }

// ErrorClass returns the audit "error_class" value for err ("" for nil).
func ErrorClass(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrRevoked):
		return "revoked"
	case errors.Is(err, ErrReauthRequired):
		return "reauth_required"
	case errors.Is(err, ErrAuthDefinitive):
		return "auth_definitive"
	case errors.Is(err, ErrConfig):
		return "config"
	case errors.Is(err, ErrPolicy):
		return "policy"
	case errors.Is(err, ErrTransient):
		return "transient"
	case errors.Is(err, ErrProvider):
		return "provider"
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrVersionConflict):
		return "conflict"
	default:
		return "unknown"
	}
}

// Process exit codes (FR-15). 77 and 78 tell supervisors not to restart-loop.
const (
	ExitOK      = 0
	ExitFailure = 1
	ExitRevoked = 77
	ExitConfig  = 78
)

// ExitCode maps err to a process exit code.
func ExitCode(err error) int {
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, ErrRevoked):
		return ExitRevoked
	case errors.Is(err, ErrConfig):
		return ExitConfig
	default:
		return ExitFailure
	}
}
