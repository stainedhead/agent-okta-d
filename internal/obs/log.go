// Package obs implements structured logging with a redaction layer and the
// audit event emitter (FR-10, FR-11, PRD section 12).
package obs

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"runtime/debug"
	"strings"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// sensitiveKeys are attribute keys whose value is always redacted, whatever it
// holds. Defence in depth behind SecretString and the Scrubber.
var sensitiveKeys = []string{
	"token", "assertion", "authorization", "password", "passwd", "secret",
	"private_key", "privatekey", "api_key", "apikey", "credential", "bearer",
}

func sensitiveKey(k string) bool {
	k = strings.ToLower(k)
	for _, s := range sensitiveKeys {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// NewLogger returns a JSON slog.Logger writing to w whose every message, key,
// attribute value (including errors and arbitrary values) is passed through
// scrub. A nil scrub uses an empty Scrubber, which still removes JWT-shaped text.
func NewLogger(w io.Writer, level slog.Leveler, scrub *domain.Scrubber) *slog.Logger {
	if scrub == nil {
		scrub = domain.NewScrubber()
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	return slog.New(&redactHandler{next: h, scrub: scrub})
}

type redactHandler struct {
	next  slog.Handler
	scrub *domain.Scrubber
}

func (h *redactHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

func (h *redactHandler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, h.scrub.Scrub(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(h.attr(a))
		return true
	})
	return h.next.Handle(ctx, nr)
}

func (h *redactHandler) WithAttrs(as []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(as))
	for i, a := range as {
		out[i] = h.attr(a)
	}
	return &redactHandler{next: h.next.WithAttrs(out), scrub: h.scrub}
}

func (h *redactHandler) WithGroup(name string) slog.Handler {
	return &redactHandler{next: h.next.WithGroup(h.scrub.Scrub(name)), scrub: h.scrub}
}

func (h *redactHandler) attr(a slog.Attr) slog.Attr {
	key := h.scrub.Scrub(a.Key)
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		gs := v.Group()
		out := make([]slog.Attr, len(gs))
		for i, g := range gs {
			out[i] = h.attr(g)
		}
		return slog.Attr{Key: key, Value: slog.GroupValue(out...)}
	}
	if sensitiveKey(a.Key) {
		return slog.String(key, domain.Redacted)
	}
	switch v.Kind() {
	case slog.KindString:
		return slog.String(key, h.scrub.Scrub(v.String()))
	case slog.KindAny:
		return slog.String(key, h.scrub.Scrub(anyString(v.Any())))
	default: // numbers, bools, durations, times cannot carry a secret
		return slog.Attr{Key: key, Value: v}
	}
}

func anyString(x any) string {
	defer func() { _ = recover() }() // a panicking String/Error method must not escape
	switch t := x.(type) {
	case nil:
		return "<nil>"
	case error:
		return t.Error()
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprintf("%+v", t)
	}
}

// Guard runs fn and converts a panic into an error. The panic value and the
// stack are scrubbed and logged at error level; the returned error carries the
// scrubbed value only. Use it around goroutine bodies and request handlers so
// a panic can never print a secret (PRD: no secrets in logs/panics).
func Guard(log *slog.Logger, scrub *domain.Scrubber, fn func() error) (err error) {
	if scrub == nil {
		scrub = domain.NewScrubber()
	}
	defer func() {
		if r := recover(); r != nil {
			msg := scrubValue(scrub, r)
			log.Error("panic recovered", "panic", msg, "stack", scrub.Scrub(string(debug.Stack())))
			err = fmt.Errorf("%w: panic: %s", domain.ErrProvider, msg)
		}
	}()
	return fn()
}

func scrubValue(scrub *domain.Scrubber, r any) string {
	return scrub.Scrub(anyString(r))
}
