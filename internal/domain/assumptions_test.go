package domain

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var markerRE = regexp.MustCompile(`ASSUMPTION\((A-?\d{2})\)`)

func normID(s string) string { return "A-" + strings.TrimPrefix(strings.TrimPrefix(s, "A"), "-") }

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// AC-016: every ASSUMPTION(Axx) marker in Go source appears in docs/assumptions.md,
// and every register row has an M0 checklist row.
func TestAssumptionMarkersAreRegistered(t *testing.T) {
	root := repoRoot(t)
	reg, err := os.ReadFile(filepath.Join(root, "docs", "assumptions.md"))
	if err != nil {
		t.Fatal(err)
	}
	chk, err := os.ReadFile(filepath.Join(root, "docs", "m0-spike-checklist.md"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 12; i++ {
		id := fmt.Sprintf("A-%02d", i)
		if !strings.Contains(string(reg), "| "+id+" ") {
			t.Errorf("register lacks %s", id)
		}
		if !strings.Contains(string(chk), "| "+id+" ") {
			t.Errorf("checklist lacks %s", id)
		}
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "specs") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "assumptions_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range markerRE.FindAllStringSubmatch(string(b), -1) {
			if id := normID(m[1]); !strings.Contains(string(reg), "| "+id+" ") {
				t.Errorf("%s: marker %s not in docs/assumptions.md", p, id)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
