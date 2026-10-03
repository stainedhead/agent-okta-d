package domain

import (
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
