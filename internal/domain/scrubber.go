package domain

import (
	"regexp"
	"slices"
	"strings"
	"sync"
)

// minScrubLen is the shortest registered secret the Scrubber will replace; a
// shorter value would mangle ordinary text.
const minScrubLen = 6

var jwtLike = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}(\.[A-Za-z0-9_-]*)?`)

// Scrubber removes known secret values, and anything shaped like a JWT, from
// free text. The logging layer applies it to every message, attribute and
// recovered panic value as defence in depth behind SecretString. It is safe
// for concurrent use.
type Scrubber struct {
	mu      sync.RWMutex
	secrets []string
}

// NewScrubber returns an empty Scrubber.
func NewScrubber() *Scrubber { return &Scrubber{} }

// Add registers secrets to scrub. Values shorter than 6 bytes are ignored.
func (s *Scrubber) Add(secrets ...SecretString) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sec := range secrets {
		v := sec.Reveal()
		if len(v) >= minScrubLen && !slices.Contains(s.secrets, v) {
			s.secrets = append(s.secrets, v)
		}
	}
	// longest first so a secret containing another is replaced whole
	slices.SortFunc(s.secrets, func(a, b string) int { return len(b) - len(a) })
}

// Reset forgets every registered secret (for example on revoke).
func (s *Scrubber) Reset() {
	s.mu.Lock()
	s.secrets = nil
	s.mu.Unlock()
}

// Scrub returns text with registered secrets and JWT-shaped strings replaced
// by Redacted.
func (s *Scrubber) Scrub(text string) string {
	s.mu.RLock()
	for _, v := range s.secrets {
		text = strings.ReplaceAll(text, v, Redacted)
	}
	s.mu.RUnlock()
	return jwtLike.ReplaceAllString(text, Redacted)
}
