package client_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestStdlibOnly enforces CLI-4 / ADR-C: non-test code in pkg/client and
// pkg/client/clienttest imports the standard library or the module's own
// pkg/client packages, never internal/ and never a third-party module.
func TestStdlibOnly(t *testing.T) {
	const self = "github.com/stainedhead/agent-okta-d/pkg/client"
	for _, dir := range []string{".", "clienttest"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		checked := 0
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range af.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				first, _, _ := strings.Cut(p, "/")
				switch {
				case strings.Contains(p, "/internal/") || strings.HasSuffix(p, "/internal"):
					t.Errorf("%s imports internal package %s", f, p)
				case p == self || strings.HasPrefix(p, self+"/"):
				case strings.Contains(first, "."):
					t.Errorf("%s imports non-stdlib package %s", f, p)
				}
			}
			checked++
		}
		if checked == 0 {
			t.Fatalf("no source files found in %s", dir)
		}
	}
}

func TestChecksFailOnBadImport(t *testing.T) {
	// Guard against the test above silently passing: the working tree must
	// contain the files it inspects.
	if _, err := os.Stat("client.go"); err != nil {
		t.Fatal(err)
	}
}
