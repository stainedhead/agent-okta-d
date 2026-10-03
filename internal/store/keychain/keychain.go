// Package keychain is the OS-keychain SecretStore (PRD MG-3, FR-18). The
// portable Store works over a narrow Backend; the native macOS backend sits
// behind a build tag with a stub for every other build.
package keychain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// ErrItemNotFound is returned by a Backend for a missing item.
var ErrItemNotFound = errors.New("keychain item not found")

// Backend reads and writes one generic-password item per account within a
// fixed service.
type Backend interface {
	Get(ctx context.Context, account string) (string, error)
	Set(ctx context.Context, account, value string) error
}

// Store implements domain.SecretStore over a Backend. The keychain has no
// native versions, so the version is a digest of the stored value and
// compare-and-set is serialised in-process (the daemon is the sole writer).
type Store struct {
	mu sync.Mutex
	b  Backend
}

var _ domain.SecretStore = (*Store)(nil)

// New wraps b.
func New(b Backend) *Store { return &Store{b: b} }

func versionOf(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:16])
}

func checkKey(key string) error {
	if key == "" {
		return domain.NewConfigError("store.key", "must not be empty")
	}
	return nil
}

// Get implements domain.SecretStore.
func (s *Store) Get(ctx context.Context, key string) (domain.SecretValue, error) {
	if err := checkKey(key); err != nil {
		return domain.SecretValue{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.get(ctx, key)
}

func (s *Store) get(ctx context.Context, key string) (domain.SecretValue, error) {
	v, err := s.b.Get(ctx, key)
	switch {
	case errors.Is(err, ErrItemNotFound):
		return domain.SecretValue{}, domain.ErrNotFound
	case err != nil:
		return domain.SecretValue{}, domain.Wrap(domain.ErrProvider, err)
	}
	return domain.SecretValue{Value: domain.NewSecret(v), Version: versionOf(v)}, nil
}

// Put implements domain.SecretStore.
func (s *Store) Put(ctx context.Context, key string, value domain.SecretString, expected string) (string, error) {
	if err := checkKey(key); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.get(ctx, key)
	switch {
	case errors.Is(err, domain.ErrNotFound):
		if expected != "" {
			return "", domain.ErrVersionConflict
		}
	case err != nil:
		return "", err
	default:
		if expected != cur.Version {
			return "", domain.ErrVersionConflict
		}
	}
	if err := s.b.Set(ctx, key, value.Reveal()); err != nil {
		return "", domain.Wrap(domain.ErrProvider, err)
	}
	return versionOf(value.Reveal()), nil
}
