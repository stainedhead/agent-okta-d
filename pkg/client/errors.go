package client

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Sentinel errors. Match with errors.Is; the concrete error may be an
// *APIError carrying the status, state and retry hint.
var (
	// ErrReauthRequired means a user must re-enroll the provider (401).
	ErrReauthRequired = errors.New("agent-okta-d: reauthentication required")
	// ErrRevoked means the daemon is revoked and serves nothing (403).
	ErrRevoked = errors.New("agent-okta-d: revoked")
	// ErrDegraded means the daemon cannot serve right now; retry after the
	// hint carried by the *APIError (503).
	ErrDegraded = errors.New("agent-okta-d: degraded")
	// ErrUnauthorized means the caller is not allowed to use the daemon (403).
	ErrUnauthorized = errors.New("agent-okta-d: caller not authorized")
	// ErrNotConfigured means the provider is unknown or disabled (404).
	ErrNotConfigured = errors.New("agent-okta-d: provider not configured")
	// ErrDaemonUnavailable means the daemon socket could not be reached or
	// the request timed out.
	ErrDaemonUnavailable = errors.New("agent-okta-d: daemon unavailable")
	// ErrInvalidResponse means the daemon answered with something that is not
	// a valid API response. The client fails closed and returns no data.
	ErrInvalidResponse = errors.New("agent-okta-d: invalid response")
)

// Wire error codes carried in the "error" field of an error body.
const (
	codeReauthRequired = "reauth_required"
	codeRevoked        = "revoked"
	codeDegraded       = "degraded"
	codeUnauthorized   = "unauthorized"
	codeNotConfigured  = "not_configured"
)

// APIError is returned for every non-2xx daemon answer.
type APIError struct {
	// Status is the HTTP status code.
	Status int
	// Code is the wire error code ("" when the body had none).
	Code string
	// State is the daemon state reported in the body, if any.
	State State
	// RetryAfter is the retry hint (body, else Retry-After header); zero if none.
	RetryAfter time.Duration
}

// Error implements error.
func (e *APIError) Error() string {
	s := "agent-okta-d: http " + strconv.Itoa(e.Status)
	if e.Code != "" {
		s += " " + e.Code
	}
	if e.RetryAfter > 0 {
		s += fmt.Sprintf(" (retry after %s)", e.RetryAfter)
	}
	return s
}

// sentinel maps the error to its sentinel. The body code decides first and the
// HTTP status second; a bare 403 is ErrUnauthorized (fail closed).
func (e *APIError) sentinel() error {
	switch e.Code {
	case codeReauthRequired:
		return ErrReauthRequired
	case codeRevoked:
		return ErrRevoked
	case codeDegraded:
		return ErrDegraded
	case codeUnauthorized:
		return ErrUnauthorized
	case codeNotConfigured:
		return ErrNotConfigured
	}
	switch e.Status {
	case 401:
		return ErrReauthRequired
	case 403:
		return ErrUnauthorized
	case 404:
		return ErrNotConfigured
	case 503:
		return ErrDegraded
	}
	return nil
}

// Is makes errors.Is(e, ErrX) true for the sentinel the response maps to.
func (e *APIError) Is(target error) bool {
	s := e.sentinel()
	return s != nil && target == s
}

// RetryAfter extracts the daemon's retry hint from err, if it carries one.
func RetryAfter(err error) (time.Duration, bool) {
	var ae *APIError
	if errors.As(err, &ae) && ae.RetryAfter > 0 {
		return ae.RetryAfter, true
	}
	return 0, false
}
