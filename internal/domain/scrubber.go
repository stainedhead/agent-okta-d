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

const (
	// maxPerSource bounds how many rotating values one source (for example a
	// store key) keeps; older values are evicted first.
	maxPerSource = 4
	// maxStatic bounds values registered through Add.
	maxStatic = 256
)

// Scrubber removes known secret values, and anything shaped like a JWT, from
// free text. The logging layer applies it to every message, attribute and
// recovered panic value as defence in depth behind SecretString. It is safe
// for concurrent use.
type Scrubber struct {
	mu      sync.RWMutex
	bySrc   map[string][]string // oldest first
	secrets []string            // flattened, longest first
}

// NewScrubber returns an empty Scrubber.
func NewScrubber() *Scrubber { return &Scrubber{bySrc: map[string][]string{}} }

// Add registers secrets to scrub. Values shorter than 6 bytes are ignored.
// At most 256 such values are kept; the oldest are evicted first.
func (s *Scrubber) Add(secrets ...SecretString) { s.AddFrom("", secrets...) }

// AddFrom registers secrets that rotate, tagged by source (for example
// "store/<key>"). Each source keeps only its 4 most recent distinct values, so
// rotation cannot grow the list without bound. Values shorter than 6 bytes
// are ignored.
func (s *Scrubber) AddFrom(source string, secrets ...SecretString) {
	limit := maxPerSource
	if source == "" {
		limit = maxStatic
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bySrc == nil {
		s.bySrc = map[string][]string{}
	}
	list := s.bySrc[source]
	for _, sec := range secrets {
		v := sec.Reveal()
		if len(v) < minScrubLen {
			continue
		}
		if i := slices.Index(list, v); i >= 0 {
			list = slices.Delete(list, i, i+1) // refresh recency
		}
		list = append(list, v)
	}
	if len(list) > limit {
		list = slices.Clone(list[len(list)-limit:])
	}
	s.bySrc[source] = list
	s.secrets = s.secrets[:0]
	for _, l := range s.bySrc {
		for _, v := range l {
			if !slices.Contains(s.secrets, v) {
				s.secrets = append(s.secrets, v)
			}
		}
	}
	// longest first so a secret containing another is replaced whole
	slices.SortFunc(s.secrets, func(a, b string) int { return len(b) - len(a) })
}

// Reset forgets every registered secret (for example on revoke).
func (s *Scrubber) Reset() {
	s.mu.Lock()
	s.secrets = nil
	s.bySrc = map[string][]string{}
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
