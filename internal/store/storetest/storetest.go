// Package storetest is a conformance suite every domain.SecretStore
// implementation must pass.
package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// Run exercises the SecretStore contract against stores built by newStore.
// Each call to newStore must return a fresh, empty store.
func Run(t *testing.T, newStore func(t *testing.T) domain.SecretStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("get missing is ErrNotFound", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Get(ctx, "nope"); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})
	t.Run("create then get", func(t *testing.T) {
		s := newStore(t)
		v1, err := s.Put(ctx, "k", domain.NewSecret("one"), "")
		if err != nil || v1 == "" {
			t.Fatalf("put: %q %v", v1, err)
		}
		got, err := s.Get(ctx, "k")
		if err != nil || got.Value.Reveal() != "one" || got.Version != v1 {
			t.Fatalf("get = %v %v, want one/%s", got, err, v1)
		}
	})
	t.Run("create over existing conflicts", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Put(ctx, "k", domain.NewSecret("one"), ""); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Put(ctx, "k", domain.NewSecret("two"), ""); !errors.Is(err, domain.ErrVersionConflict) {
			t.Fatalf("err = %v, want ErrVersionConflict", err)
		}
	})
	t.Run("update with current version", func(t *testing.T) {
		s := newStore(t)
		v1, _ := s.Put(ctx, "k", domain.NewSecret("one"), "")
		v2, err := s.Put(ctx, "k", domain.NewSecret("two"), v1)
		if err != nil || v2 == v1 {
			t.Fatalf("v2 = %q (v1 %q) err %v", v2, v1, err)
		}
		got, _ := s.Get(ctx, "k")
		if got.Value.Reveal() != "two" || got.Version != v2 {
			t.Fatalf("get = %v", got)
		}
	})
	t.Run("stale version conflicts and keeps value", func(t *testing.T) {
		s := newStore(t)
		v1, _ := s.Put(ctx, "k", domain.NewSecret("one"), "")
		if _, err := s.Put(ctx, "k", domain.NewSecret("two"), v1); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Put(ctx, "k", domain.NewSecret("three"), v1); !errors.Is(err, domain.ErrVersionConflict) {
			t.Fatalf("err = %v, want ErrVersionConflict", err)
		}
		if got, _ := s.Get(ctx, "k"); got.Value.Reveal() != "two" {
			t.Fatalf("value = %q, want two", got.Value.Reveal())
		}
	})
	t.Run("update missing key conflicts", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Put(ctx, "k", domain.NewSecret("x"), "bogus"); !errors.Is(err, domain.ErrVersionConflict) && !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("keys are independent", func(t *testing.T) {
		s := newStore(t)
		_, _ = s.Put(ctx, "a", domain.NewSecret("A"), "")
		_, _ = s.Put(ctx, "b", domain.NewSecret("B"), "")
		a, _ := s.Get(ctx, "a")
		b, _ := s.Get(ctx, "b")
		if a.Value.Reveal() != "A" || b.Value.Reveal() != "B" {
			t.Fatalf("a=%v b=%v", a, b)
		}
	})
	t.Run("concurrent writers: exactly one wins", func(t *testing.T) {
		s := newStore(t)
		v1, _ := s.Put(ctx, "k", domain.NewSecret("base"), "")
		const n = 8
		var wg sync.WaitGroup
		errs := make([]error, n)
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = s.Put(ctx, "k", domain.NewSecret("w"), v1)
			}()
		}
		wg.Wait()
		wins := 0
		for _, err := range errs {
			switch {
			case err == nil:
				wins++
			case !errors.Is(err, domain.ErrVersionConflict):
				t.Fatalf("unexpected error %v", err)
			}
		}
		if wins != 1 {
			t.Fatalf("wins = %d, want 1", wins)
		}
	})
	t.Run("errors never contain the value", func(t *testing.T) {
		s := newStore(t)
		_, _ = s.Put(ctx, "k", domain.NewSecret("sup3r-s3cret"), "")
		_, err := s.Put(ctx, "k", domain.NewSecret("sup3r-s3cret"), "")
		if err == nil || contains(err.Error(), "sup3r-s3cret") {
			t.Fatalf("err = %v", err)
		}
	})
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
