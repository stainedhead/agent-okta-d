package keychain

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/store/storetest"
)

type fakeBackend struct {
	mu     sync.Mutex
	m      map[string]string
	getErr error
	setErr error
}

func (f *fakeBackend) Get(_ context.Context, account string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return "", f.getErr
	}
	v, ok := f.m[account]
	if !ok {
		return "", ErrItemNotFound
	}
	return v, nil
}

func (f *fakeBackend) Set(_ context.Context, account, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setErr != nil {
		return f.setErr
	}
	f.m[account] = value
	return nil
}

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) domain.SecretStore {
		return New(&fakeBackend{m: map[string]string{}})
	})
}

func TestBackendErrorsClassified(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("boom")
	s := New(&fakeBackend{m: map[string]string{}, getErr: boom})
	if _, err := s.Get(ctx, "k"); !errors.Is(err, domain.ErrProvider) || !errors.Is(err, boom) {
		t.Fatalf("get err = %v", err)
	}
	if _, err := s.Put(ctx, "k", domain.NewSecret("v"), ""); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("put err = %v", err)
	}
	s = New(&fakeBackend{m: map[string]string{}, setErr: boom})
	if _, err := s.Put(ctx, "k", domain.NewSecret("v"), ""); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("set err = %v", err)
	}
}

func TestEmptyKeyIsConfigError(t *testing.T) {
	s := New(&fakeBackend{m: map[string]string{}})
	if _, err := s.Get(context.Background(), ""); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.Put(context.Background(), "", domain.NewSecret("v"), ""); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("err = %v", err)
	}
}

func TestNativeUnavailableOnThisBuild(t *testing.T) {
	// ASSUMPTION(A-12): the native Keychain backend needs cgo on darwin and is
	// not built here; every build returns ErrConfig until it lands.
	if _, err := NewNative("svc"); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig", err)
	}
}
