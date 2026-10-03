// Package domaintest provides in-memory fakes for every interface in
// internal/domain so workstreams can test against the frozen contracts in
// parallel. All fakes are safe for concurrent use and never touch the network
// or the filesystem.
package domaintest

import (
	"context"
	"log/slog"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// Compile-time contract checks.
var (
	_ domain.Clock           = (*FakeClock)(nil)
	_ domain.Signer          = (*FakeSigner)(nil)
	_ domain.Provider        = (*FakeProvider)(nil)
	_ domain.Deps            = (*FakeDeps)(nil)
	_ domain.OktaTokenSource = (*FakeOkta)(nil)
	_ domain.SecretStore     = (*FakeStore)(nil)
	_ domain.Sink            = (*FakeSink)(nil)
	_ domain.AuditSink       = (*RecordingAudit)(nil)
	_ domain.PeerCredReader  = (*FakePeerCred)(nil)
)

// Epoch is the default start time of a FakeClock.
var Epoch = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

// FakeClock is a manually advanced Clock. Timers fire inside Advance.
type FakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

// NewFakeClock starts at Epoch.
func NewFakeClock() *FakeClock { return &FakeClock{now: Epoch} }

// Now implements domain.Clock.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// NewTimer implements domain.Clock.
func (c *FakeClock) NewTimer(d time.Duration) domain.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{c: c, ch: make(chan time.Time, 1)}
	t.arm(d)
	c.timers = append(c.timers, t)
	return t
}

// Advance moves time forward, firing due timers in deadline order.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	target := c.now.Add(d)
	for {
		var next *fakeTimer
		for _, t := range c.timers {
			if t.active && !t.at.After(target) && (next == nil || t.at.Before(next.at)) {
				next = t
			}
		}
		if next == nil {
			break
		}
		c.now = next.at
		next.active = false
		select {
		case next.ch <- next.at:
		default:
		}
	}
	c.now = target
	c.mu.Unlock()
}

// PendingTimers counts armed timers.
func (c *FakeClock) PendingTimers() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, t := range c.timers {
		if t.active {
			n++
		}
	}
	return n
}

type fakeTimer struct {
	c      *FakeClock
	ch     chan time.Time
	at     time.Time
	active bool
}

func (t *fakeTimer) arm(d time.Duration) { t.at, t.active = t.c.now.Add(d), true }
func (t *fakeTimer) C() <-chan time.Time { return t.ch }
func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := t.active
	t.active = false
	return was
}
func (t *fakeTimer) Reset(d time.Duration) bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := t.active
	t.arm(d)
	return was
}

// FakeSigner returns a deterministic non-cryptographic signature.
type FakeSigner struct {
	KID string
	Err error
	mu  sync.Mutex
	// Calls records each signed input.
	Calls [][]byte
}

// Sign implements domain.Signer; the signature is "sig:"+alg+":"+input.
func (s *FakeSigner) Sign(_ context.Context, alg string, in []byte) ([]byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Err != nil {
		return nil, "", s.Err
	}
	s.Calls = append(s.Calls, slices.Clone(in))
	kid := s.KID
	if kid == "" {
		kid = "fake-kid"
	}
	return append([]byte("sig:"+alg+":"), in...), kid, nil
}

// Public implements domain.Signer.
func (s *FakeSigner) Public() ([]byte, error) {
	if s.Err != nil {
		return nil, s.Err
	}
	return []byte(`{"kty":"RSA","kid":"fake-kid","n":"AQAB","e":"AQAB"}`), nil
}

// FakeProvider is a scriptable domain.Provider.
type FakeProvider struct {
	ProviderName string
	SinkSpecs    []domain.SinkSpec
	// MintFn overrides Mint; the default returns a 1 h bearer credential.
	MintFn   func(ctx context.Context, d domain.Deps) (domain.Credential, error)
	RevokeFn func(ctx context.Context, c domain.Credential) error
	ProbeFn  func(ctx context.Context, c domain.Credential) error

	mu                     sync.Mutex
	Mints, Revokes, Probes int
}

// Name implements domain.Provider.
func (p *FakeProvider) Name() string { return p.ProviderName }

// Sinks implements domain.Provider.
func (p *FakeProvider) Sinks() []domain.SinkSpec { return p.SinkSpecs }

// Mint implements domain.Provider.
func (p *FakeProvider) Mint(ctx context.Context, d domain.Deps) (domain.Credential, error) {
	p.mu.Lock()
	p.Mints++
	n := p.Mints
	p.mu.Unlock()
	if p.MintFn != nil {
		return p.MintFn(ctx, d)
	}
	now := d.Clock().Now()
	return domain.Credential{
		Kind: domain.KindBearer, Value: domain.NewSecret("fake-token-" + string(rune('0'+n%10))),
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		Meta: map[string]string{domain.MetaAudience: "api://" + p.ProviderName},
	}, nil
}

// Revoke implements domain.Provider.
func (p *FakeProvider) Revoke(ctx context.Context, c domain.Credential) error {
	p.mu.Lock()
	p.Revokes++
	p.mu.Unlock()
	if p.RevokeFn != nil {
		return p.RevokeFn(ctx, c)
	}
	return nil
}

// Probe implements domain.Provider.
func (p *FakeProvider) Probe(ctx context.Context, c domain.Credential) error {
	p.mu.Lock()
	p.Probes++
	p.mu.Unlock()
	if p.ProbeFn != nil {
		return p.ProbeFn(ctx, c)
	}
	return nil
}

// FakeOkta is a scriptable domain.OktaTokenSource.
type FakeOkta struct {
	Clock domain.Clock
	// TokenFn overrides the default 1 h token.
	TokenFn func(ctx context.Context, req domain.OktaTokenRequest) (domain.OktaToken, error)

	mu       sync.Mutex
	Requests []domain.OktaTokenRequest
}

// Token implements domain.OktaTokenSource.
func (o *FakeOkta) Token(ctx context.Context, req domain.OktaTokenRequest) (domain.OktaToken, error) {
	o.mu.Lock()
	o.Requests = append(o.Requests, req)
	o.mu.Unlock()
	if o.TokenFn != nil {
		return o.TokenFn(ctx, req)
	}
	now := Epoch
	if o.Clock != nil {
		now = o.Clock.Now()
	}
	return domain.OktaToken{
		AccessToken: domain.NewSecret("okta-fake-token"), TokenType: "Bearer",
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), Audience: "api://" + req.AuthServer, Scope: req.Scope, JTI: "jti-fake",
	}, nil
}

// FakeStore is an in-memory compare-and-set SecretStore.
type FakeStore struct {
	mu   sync.Mutex
	data map[string]domain.SecretValue
	n    int
	// PutErr, when non-nil, fails every Put (to test "persist before use").
	PutErr error
	// Puts counts successful writes.
	Puts int
}

// Get implements domain.SecretStore.
func (s *FakeStore) Get(_ context.Context, key string) (domain.SecretValue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	if !ok {
		return domain.SecretValue{}, domain.ErrNotFound
	}
	return v, nil
}

// Put implements domain.SecretStore.
func (s *FakeStore) Put(_ context.Context, key string, value domain.SecretString, expected string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.PutErr != nil {
		return "", s.PutErr
	}
	cur, ok := s.data[key]
	if (!ok && expected != "") || (ok && cur.Version != expected) {
		return "", domain.ErrVersionConflict
	}
	if s.data == nil {
		s.data = map[string]domain.SecretValue{}
	}
	s.n++
	v := "v" + itoa(s.n)
	s.data[key] = domain.SecretValue{Value: value, Version: v}
	s.Puts++
	return v, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// FakeSink records sink writes in memory.
type FakeSink struct {
	mu    sync.Mutex
	files map[string]string
	// WriteErr, when non-nil, fails every Write.
	WriteErr error
	// Ops is the ordered log of "write:<path>" and "remove:<path>".
	Ops []string
}

// Write implements domain.Sink.
func (s *FakeSink) Write(_ context.Context, spec domain.SinkSpec, content domain.SecretString) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.WriteErr != nil {
		return s.WriteErr
	}
	if s.files == nil {
		s.files = map[string]string{}
	}
	v := content.Reveal()
	if spec.Format == domain.SinkRawNL {
		v += "\n"
	}
	s.files[spec.Path] = v
	s.Ops = append(s.Ops, "write:"+spec.Path)
	return nil
}

// Remove implements domain.Sink.
func (s *FakeSink) Remove(_ context.Context, spec domain.SinkSpec) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.files, spec.Path)
	s.Ops = append(s.Ops, "remove:"+spec.Path)
	return nil
}

// Content returns the current content of path.
func (s *FakeSink) Content(path string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.files[path]
	return v, ok
}

// RecordingAudit stores emitted events.
type RecordingAudit struct {
	mu     sync.Mutex
	events []domain.AuditEvent
}

// Emit implements domain.AuditSink.
func (a *RecordingAudit) Emit(_ context.Context, e domain.AuditEvent) {
	a.mu.Lock()
	a.events = append(a.events, e)
	a.mu.Unlock()
}

// Events returns a copy of the recorded events.
func (a *RecordingAudit) Events() []domain.AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.events)
}

// FakePeerCred returns a fixed caller (or error) for every connection.
type FakePeerCred struct {
	Caller domain.CallerInfo
	Err    error
}

// Read implements domain.PeerCredReader.
func (p *FakePeerCred) Read(net.Conn) (domain.CallerInfo, error) { return p.Caller, p.Err }

// FakeDeps is a domain.Deps built from fakes. Zero fields get defaults from
// NewFakeDeps.
type FakeDeps struct {
	ClockV  domain.Clock
	OktaV   domain.OktaTokenSource
	Creds   map[string]domain.Credential // answers Credential(provider)
	Stores  map[string]domain.SecretStore
	LoggerV *slog.Logger
	AuditV  domain.AuditSink
}

// NewFakeDeps returns Deps wired to a FakeClock, FakeOkta, empty maps, a
// discarding logger and a RecordingAudit.
func NewFakeDeps() *FakeDeps {
	clk := NewFakeClock()
	return &FakeDeps{
		ClockV: clk, OktaV: &FakeOkta{Clock: clk}, Creds: map[string]domain.Credential{}, Stores: map[string]domain.SecretStore{},
		LoggerV: slog.New(slog.DiscardHandler), AuditV: &RecordingAudit{},
	}
}

// Clock implements domain.Deps.
func (d *FakeDeps) Clock() domain.Clock { return d.ClockV }

// Okta implements domain.Deps.
func (d *FakeDeps) Okta() domain.OktaTokenSource { return d.OktaV }

// Credential implements domain.Deps; unknown providers yield ErrNotFound.
func (d *FakeDeps) Credential(_ context.Context, provider string) (domain.Credential, error) {
	c, ok := d.Creds[provider]
	if !ok {
		return domain.Credential{}, domain.ErrNotFound
	}
	return c, nil
}

// Store implements domain.Deps; unknown stores yield ErrConfig.
func (d *FakeDeps) Store(name string) (domain.SecretStore, error) {
	s, ok := d.Stores[name]
	if !ok {
		return nil, domain.NewConfigError("stores."+name, "not configured")
	}
	return s, nil
}

// Logger implements domain.Deps.
func (d *FakeDeps) Logger() *slog.Logger { return d.LoggerV }

// Audit implements domain.Deps.
func (d *FakeDeps) Audit() domain.AuditSink { return d.AuditV }
