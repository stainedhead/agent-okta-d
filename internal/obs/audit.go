package obs

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// Audit writes one JSON line per AuditEvent (PRD section 12 fields). It never
// fails or panics the caller: write and marshal errors are counted. Every
// string field is scrubbed before encoding.
type Audit struct {
	mu      sync.Mutex
	w       io.Writer
	agentID string
	clock   domain.Clock
	scrub   *domain.Scrubber
	dropped atomic.Int64
}

var _ domain.AuditSink = (*Audit)(nil)

// NewAudit returns an emitter. clock stamps events with a zero TS; agentID
// fills events with an empty AgentID.
func NewAudit(w io.Writer, agentID string, clock domain.Clock, scrub *domain.Scrubber) *Audit {
	if scrub == nil {
		scrub = domain.NewScrubber()
	}
	return &Audit{w: w, agentID: agentID, clock: clock, scrub: scrub}
}

// Dropped reports how many events could not be written.
func (a *Audit) Dropped() int64 { return a.dropped.Load() }

// Emit implements domain.AuditSink.
func (a *Audit) Emit(_ context.Context, e domain.AuditEvent) {
	defer func() {
		if recover() != nil {
			a.dropped.Add(1)
		}
	}()
	if e.TS.IsZero() && a.clock != nil {
		e.TS = a.clock.Now()
	}
	e.TS = e.TS.UTC()
	if e.AgentID == "" {
		e.AgentID = a.agentID
	}
	s := a.scrub.Scrub
	e.AgentID = s(e.AgentID)
	e.Event = domain.AuditEventType(s(string(e.Event)))
	e.Provider, e.Audience, e.JTI = s(e.Provider), s(e.Audience), s(e.JTI)
	e.CallerExe, e.Result = s(e.CallerExe), s(e.Result)
	e.ErrorClass, e.Detail = s(e.ErrorClass), s(e.Detail)
	if e.ExpiresAt != nil {
		t := e.ExpiresAt.UTC()
		e.ExpiresAt = &t
	}
	b, err := json.Marshal(e)
	if err != nil {
		a.dropped.Add(1)
		return
	}
	b = append(b, '\n')
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.w.Write(b); err != nil {
		a.dropped.Add(1)
	}
}
