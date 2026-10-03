package domaintest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

var ctx = context.Background()

func TestFakeClock(t *testing.T) {
	c := NewFakeClock()
	a, b := c.NewTimer(time.Minute), c.NewTimer(2*time.Minute)
	if c.PendingTimers() != 2 {
		t.Fatal("pending")
	}
	c.Advance(90 * time.Second)
	select {
	case at := <-a.C():
		if !at.Equal(Epoch.Add(time.Minute)) {
			t.Fatal(at)
		}
	default:
		t.Fatal("a not fired")
	}
	select {
	case <-b.C():
		t.Fatal("b fired early")
	default:
	}
	if !c.Now().Equal(Epoch.Add(90 * time.Second)) {
		t.Fatal("now")
	}
	if !b.Stop() || b.Stop() {
		t.Fatal("Stop semantics")
	}
	if b.Reset(time.Second) {
		t.Fatal("Reset of stopped timer reports inactive")
	}
	c.Advance(time.Second)
	select {
	case <-b.C():
	default:
		t.Fatal("reset timer not fired")
	}
	if a.Reset(time.Hour) || c.PendingTimers() != 1 {
		t.Fatal("pending after reset")
	}
}

func TestFakeSignerAndProvider(t *testing.T) {
	s := &FakeSigner{}
	sig, kid, err := s.Sign(ctx, "RS256", []byte("x"))
	if err != nil || kid != "fake-kid" || string(sig) != "sig:RS256:x" || len(s.Calls) != 1 {
		t.Fatal(sig, kid, err)
	}
	if j, err := s.Public(); err != nil || len(j) == 0 {
		t.Fatal("Public")
	}
	boom := errors.New("boom")
	s = &FakeSigner{KID: "k", Err: boom}
	if _, _, err := s.Sign(ctx, "RS256", nil); !errors.Is(err, boom) {
		t.Fatal("err")
	}
	if _, err := s.Public(); !errors.Is(err, boom) {
		t.Fatal("err")
	}

	d := NewFakeDeps()
	p := &FakeProvider{ProviderName: "aws", SinkSpecs: []domain.SinkSpec{{Path: "/p"}}}
	c, err := p.Mint(ctx, d)
	if err != nil || c.Validate() != nil || c.Audience() != "api://aws" || p.Name() != "aws" || len(p.Sinks()) != 1 {
		t.Fatal(c, err)
	}
	if p.Revoke(ctx, c) != nil || p.Probe(ctx, c) != nil || p.Mints != 1 || p.Revokes != 1 || p.Probes != 1 {
		t.Fatal("counters")
	}
	p.MintFn = func(context.Context, domain.Deps) (domain.Credential, error) { return domain.Credential{}, boom }
	p.RevokeFn = func(context.Context, domain.Credential) error { return boom }
	p.ProbeFn = func(context.Context, domain.Credential) error { return boom }
	if _, err := p.Mint(ctx, d); !errors.Is(err, boom) || !errors.Is(p.Revoke(ctx, c), boom) || !errors.Is(p.Probe(ctx, c), boom) {
		t.Fatal("overrides")
	}
}

func TestFakeOktaAndDeps(t *testing.T) {
	d := NewFakeDeps()
	tok, err := d.Okta().Token(ctx, domain.OktaTokenRequest{AuthServer: "agents-aws", Scope: "s"})
	if err != nil || tok.Audience != "api://agents-aws" || !tok.ExpiresAt.After(tok.IssuedAt) {
		t.Fatal(tok, err)
	}
	o := &FakeOkta{TokenFn: func(context.Context, domain.OktaTokenRequest) (domain.OktaToken, error) {
		return domain.OktaToken{}, domain.ErrAuthDefinitive
	}}
	if _, err := o.Token(ctx, domain.OktaTokenRequest{}); !errors.Is(err, domain.ErrAuthDefinitive) || len(o.Requests) != 1 {
		t.Fatal("TokenFn")
	}
	if tok, _ := (&FakeOkta{}).Token(ctx, domain.OktaTokenRequest{}); !tok.IssuedAt.Equal(Epoch) {
		t.Fatal("default epoch")
	}
	if _, err := d.Credential(ctx, "none"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("missing cred")
	}
	d.Creds["aws"] = domain.Credential{Kind: domain.KindBearer}
	if c, err := d.Credential(ctx, "aws"); err != nil || c.Kind != domain.KindBearer {
		t.Fatal("cred")
	}
	if _, err := d.Store("x"); !errors.Is(err, domain.ErrConfig) {
		t.Fatal("missing store")
	}
	d.Stores["x"] = &FakeStore{}
	if s, err := d.Store("x"); err != nil || s == nil {
		t.Fatal("store")
	}
	if d.Clock() == nil || d.Logger() == nil || d.Audit() == nil {
		t.Fatal("accessors")
	}
}

func TestFakeStoreCAS(t *testing.T) {
	s := &FakeStore{}
	if _, err := s.Get(ctx, "k"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("get missing")
	}
	if _, err := s.Put(ctx, "k", domain.NewSecret("a"), "v9"); !errors.Is(err, domain.ErrVersionConflict) {
		t.Fatal("create with version")
	}
	v1, err := s.Put(ctx, "k", domain.NewSecret("a"), "")
	if err != nil || v1 != "v1" {
		t.Fatal(v1, err)
	}
	if _, err := s.Put(ctx, "k", domain.NewSecret("b"), ""); !errors.Is(err, domain.ErrVersionConflict) {
		t.Fatal("stale")
	}
	for i := 0; i < 10; i++ {
		var e error
		v1, e = s.Put(ctx, "k", domain.NewSecret("c"), v1)
		if e != nil {
			t.Fatal(e)
		}
	}
	if v1 != "v11" {
		t.Fatal(v1)
	}
	got, _ := s.Get(ctx, "k")
	if got.Value.Reveal() != "c" || got.Version != "v11" || s.Puts != 11 {
		t.Fatal(got)
	}
	s.PutErr = errors.New("down")
	if _, err := s.Put(ctx, "k", domain.NewSecret("d"), "v11"); err == nil {
		t.Fatal("PutErr")
	}
	if itoa(0) != "0" {
		t.Fatal("itoa")
	}
}

func TestFakeSinkAuditPeer(t *testing.T) {
	s := &FakeSink{}
	sp := domain.SinkSpec{Path: "/a", Format: domain.SinkRawNL}
	if err := s.Write(ctx, sp, domain.NewSecret("t")); err != nil {
		t.Fatal(err)
	}
	if v, ok := s.Content("/a"); !ok || v != "t\n" {
		t.Fatal(v)
	}
	_ = s.Remove(ctx, sp)
	if _, ok := s.Content("/a"); ok || len(s.Ops) != 2 || s.Ops[1] != "remove:/a" {
		t.Fatal(s.Ops)
	}
	s.WriteErr = errors.New("disk")
	if s.Write(ctx, sp, domain.NewSecret("t")) == nil {
		t.Fatal("WriteErr")
	}

	a := &RecordingAudit{}
	a.Emit(ctx, domain.AuditEvent{Event: domain.AuditMint})
	if ev := a.Events(); len(ev) != 1 || ev[0].Event != domain.AuditMint {
		t.Fatal("audit")
	}

	pc := &FakePeerCred{Caller: domain.CallerInfo{UID: 1, GID: 2}}
	if ci, err := pc.Read(nil); err != nil || ci.GID != 2 {
		t.Fatal("peer")
	}
}
