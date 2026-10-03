package app

import (
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// RealClock is the production domain.Clock.
type RealClock struct{}

var _ domain.Clock = RealClock{}

// Now implements domain.Clock.
func (RealClock) Now() time.Time { return time.Now() }

// NewTimer implements domain.Clock.
func (RealClock) NewTimer(d time.Duration) domain.Timer { return &realTimer{t: time.NewTimer(d)} }

type realTimer struct{ t *time.Timer }

func (r *realTimer) C() <-chan time.Time        { return r.t.C }
func (r *realTimer) Stop() bool                 { return r.t.Stop() }
func (r *realTimer) Reset(d time.Duration) bool { return r.t.Reset(d) }
