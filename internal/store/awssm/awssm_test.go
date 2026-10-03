package awssm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/store/storetest"
)

// fakeSM models Secrets Manager version staging: AWSCURRENT is held by one
// version and moving it requires naming the current holder.
type fakeSM struct {
	mu       sync.Mutex
	secrets  map[string]*fakeSecret
	n        int
	getErr   error
	putErr   error
	moveErr  error
	createEr error
	calls    []string
}

type fakeSecret struct {
	versions map[string]string
	current  string
}

func newFake() *fakeSM { return &fakeSM{secrets: map[string]*fakeSecret{}} }

func (f *fakeSM) id() string { f.n++; return fmt.Sprintf("v%d", f.n) }

func (f *fakeSM) GetSecretValue(_ context.Context, id string) (SecretVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "get")
	if f.getErr != nil {
		return SecretVersion{}, f.getErr
	}
	s, ok := f.secrets[id]
	if !ok {
		return SecretVersion{}, ErrResourceNotFound
	}
	return SecretVersion{Value: s.versions[s.current], VersionID: s.current}, nil
}

func (f *fakeSM) CreateSecret(_ context.Context, id, value, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "create")
	if f.createEr != nil {
		return "", f.createEr
	}
	if _, ok := f.secrets[id]; ok {
		return "", ErrResourceExists
	}
	v := f.id()
	f.secrets[id] = &fakeSecret{versions: map[string]string{v: value}, current: v}
	return v, nil
}

func (f *fakeSM) PutSecretValue(_ context.Context, id, value, _ string, stages []string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "put:"+strings.Join(stages, ","))
	if f.putErr != nil {
		return "", f.putErr
	}
	s, ok := f.secrets[id]
	if !ok {
		return "", ErrResourceNotFound
	}
	v := f.id()
	s.versions[v] = value
	return v, nil
}

func (f *fakeSM) MoveCurrent(_ context.Context, id, from, to string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "move")
	if f.moveErr != nil {
		return f.moveErr
	}
	s := f.secrets[id]
	if s == nil || s.current != from {
		return ErrStageNotHeld
	}
	s.current = to
	return nil
}

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) domain.SecretStore { return New(newFake(), "pre/") })
}

func TestKeyPrefixAndStaging(t *testing.T) {
	f := newFake()
	s := New(f, "agents/a1/")
	ctx := context.Background()
	v1, err := s.Put(ctx, "gh", domain.NewSecret("one"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.secrets["agents/a1/gh"]; !ok {
		t.Fatal("secret id not prefixed")
	}
	if _, err := s.Put(ctx, "gh", domain.NewSecret("two"), v1); err != nil {
		t.Fatal(err)
	}
	// New values are staged as AWSPENDING and promoted by a guarded move.
	joined := strings.Join(f.calls, " ")
	if !strings.Contains(joined, "put:AWSPENDING move") {
		t.Fatalf("calls = %s", joined)
	}
}

func TestStaleVersionDetectedAtMove(t *testing.T) {
	// A writer that passed the early check but lost the race fails on the guarded move.
	f := newFake()
	s := New(f, "")
	ctx := context.Background()
	v1, _ := s.Put(ctx, "k", domain.NewSecret("one"), "")
	f.moveErr = ErrStageNotHeld
	if _, err := s.Put(ctx, "k", domain.NewSecret("two"), v1); !errors.Is(err, domain.ErrVersionConflict) {
		t.Fatalf("err = %v", err)
	}
}

func TestErrorClassification(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("boom")
	trans := domain.NewTransient(boom, 0)
	cases := []struct {
		name  string
		mut   func(*fakeSM)
		do    func(s *Store) error
		want  error
		other error
	}{
		{"get provider", func(f *fakeSM) { f.getErr = boom }, func(s *Store) error { _, e := s.Get(ctx, "k"); return e }, domain.ErrProvider, boom},
		{"get transient passthrough", func(f *fakeSM) { f.getErr = trans }, func(s *Store) error { _, e := s.Get(ctx, "k"); return e }, domain.ErrTransient, nil},
		{"create fails", func(f *fakeSM) { f.createEr = boom }, func(s *Store) error { _, e := s.Put(ctx, "k", domain.NewSecret("v"), ""); return e }, domain.ErrProvider, boom},
		{"put fails", func(f *fakeSM) { f.seed("k"); f.putErr = boom }, func(s *Store) error { _, e := s.Put(ctx, "k", domain.NewSecret("v"), "v1"); return e }, domain.ErrProvider, boom},
		{"move fails", func(f *fakeSM) { f.seed("k"); f.moveErr = boom }, func(s *Store) error { _, e := s.Put(ctx, "k", domain.NewSecret("v"), "v1"); return e }, domain.ErrProvider, boom},
		{"put pre-get fails", func(f *fakeSM) { f.getErr = boom }, func(s *Store) error { _, e := s.Put(ctx, "k", domain.NewSecret("v"), "v1"); return e }, domain.ErrProvider, boom},
		{"update missing", func(f *fakeSM) {}, func(s *Store) error { _, e := s.Put(ctx, "k", domain.NewSecret("v"), "v1"); return e }, domain.ErrVersionConflict, nil},
		{"empty key", func(f *fakeSM) {}, func(s *Store) error { _, e := s.Get(ctx, ""); return e }, domain.ErrConfig, nil},
		{"empty key put", func(f *fakeSM) {}, func(s *Store) error { _, e := s.Put(ctx, "", domain.NewSecret("v"), ""); return e }, domain.ErrConfig, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			c.mut(f)
			err := c.do(New(f, ""))
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if c.other != nil && !errors.Is(err, c.other) {
				t.Fatalf("err = %v lost cause", err)
			}
		})
	}
}

func (f *fakeSM) seed(id string) {
	f.secrets[id] = &fakeSecret{versions: map[string]string{"v1": "x"}, current: "v1"}
	f.n = 1
}

func TestTokenIsUniquePerAttempt(t *testing.T) {
	a, b := newToken(), newToken()
	if a == b || len(a) < 32 {
		t.Fatalf("tokens %q %q", a, b)
	}
}
