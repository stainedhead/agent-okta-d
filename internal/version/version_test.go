package version

import "testing"

func TestString(t *testing.T) {
	Version, Commit, Date = "1.2.3", "abc", "2026-10-03"
	if got := String(); got != "1.2.3 (commit abc, built 2026-10-03)" {
		t.Fatal(got)
	}
}
