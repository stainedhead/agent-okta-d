package cache

import (
	"errors"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// ErrDegraded is matched by errors.Is for a *DegradedError.
var ErrDegraded = errors.New("credential degraded")

// DegradedError is returned while an entry is degraded: the API answers 503
// with Retry-After set from RetryAfter. It also matches domain.ErrTransient.
type DegradedError struct {
	Provider   string
	RetryAfter time.Duration
	Cause      error
}

// Error implements error.
func (e *DegradedError) Error() string {
	if e.Cause == nil {
		return "provider " + e.Provider + ": credential degraded"
	}
	return "provider " + e.Provider + ": credential degraded: " + e.Cause.Error()
}

// Unwrap exposes the last refresh failure.
func (e *DegradedError) Unwrap() error { return e.Cause }

// Is matches ErrDegraded and domain.ErrTransient.
func (e *DegradedError) Is(target error) bool {
	return target == ErrDegraded || target == domain.ErrTransient
}
