package obs

import (
	"context"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// ScrubStore wraps st so every value read from or written to it (refresh
// tokens, OAuth device tokens) is registered with scrub, tagged by store key.
// Rotating values are bounded per key by the Scrubber. A nil scrub returns st.
func ScrubStore(st domain.SecretStore, scrub *domain.Scrubber) domain.SecretStore {
	if scrub == nil || st == nil {
		return st
	}
	return scrubStore{st: st, scrub: scrub}
}

type scrubStore struct {
	st    domain.SecretStore
	scrub *domain.Scrubber
}

func (s scrubStore) Get(ctx context.Context, key string) (domain.SecretValue, error) {
	v, err := s.st.Get(ctx, key)
	if err == nil {
		s.scrub.AddFrom("store/"+key, v.Value)
	}
	return v, err
}

func (s scrubStore) Put(ctx context.Context, key string, value domain.SecretString, expectedVersion string) (string, error) {
	// Register before writing: even a failed write may surface the value in an error.
	s.scrub.AddFrom("store/"+key, value)
	return s.st.Put(ctx, key, value, expectedVersion)
}
