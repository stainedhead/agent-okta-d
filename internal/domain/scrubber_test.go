package domain

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestScrubber(t *testing.T) {
	s := NewScrubber()
	s.Add(NewSecret("hunter2-long"), NewSecret("hunter2-long"), NewSecret("abc"), NewSecret("hunter2-long-extended"))
	in := "a hunter2-long b hunter2-long-extended c abc"
	out := s.Scrub(in)
	if strings.Contains(out, "hunter2") || !strings.Contains(out, "abc") {
		t.Fatalf("%q", out)
	}
	if got := s.Scrub("Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln done"); strings.Contains(got, "eyJ") || !strings.HasSuffix(got, "done") {
		t.Fatalf("jwt: %q", got)
	}
	s.Reset()
	if s.Scrub("hunter2-long") != "hunter2-long" {
		t.Fatal("Reset")
	}
}

func TestScrubberConcurrent(t *testing.T) {
	s := NewScrubber()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Add(NewSecret(strings.Repeat("x", 8+i)))
			_ = s.Scrub("xxxxxxxxxxxx")
		}()
	}
	wg.Wait()
}

func TestScrubberBoundsRotatingSources(t *testing.T) {
	s := NewScrubber()
	s.Add(NewSecret("static-secret-1"))
	for i := range 100 {
		s.AddFrom("store/rt", NewSecret(fmt.Sprintf("refresh-token-%03d", i)))
	}
	s.AddFrom("store/rt", NewSecret("refresh-token-099")) // duplicate: no growth
	if n := len(s.secrets); n != 1+maxPerSource {
		t.Fatalf("list size %d, want %d", n, 1+maxPerSource)
	}
	if got := s.Scrub("a refresh-token-099 b refresh-token-096 c static-secret-1"); strings.Contains(got, "token-09") || strings.Contains(got, "static") {
		t.Fatalf("recent values not scrubbed: %q", got)
	}
	if got := s.Scrub("refresh-token-000"); got != "refresh-token-000" {
		t.Fatalf("evicted value still scrubbed: %q", got)
	}
	for i := range maxStatic + 10 {
		s.Add(NewSecret(fmt.Sprintf("static-value-%04d", i)))
	}
	if n := len(s.bySrc[""]); n != maxStatic {
		t.Fatalf("static size %d", n)
	}
	var z Scrubber // zero value usable
	z.AddFrom("x", NewSecret("zero-value-ok"))
	if z.Scrub("zero-value-ok") != Redacted {
		t.Fatal("zero value")
	}
}
