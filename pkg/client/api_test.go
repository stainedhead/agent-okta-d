package client_test

import (
	"bytes"
	"flag"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/api.txt")

// TestExportedAPISnapshot (CLI-6) fails whenever the exported surface of
// pkg/client or pkg/client/clienttest changes. Review the diff, decide the
// semver impact (REL-7), then run: go test ./pkg/client -run Snapshot -update
func TestExportedAPISnapshot(t *testing.T) {
	var lines []string
	for _, dir := range []string{".", "clienttest"} {
		lines = append(lines, exported(t, dir)...)
	}
	got := strings.Join(lines, "\n") + "\n"
	path := filepath.Join("testdata", "api.txt")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Fatalf("exported API changed; review and run with -update\n--- got ---\n%s", got)
	}
}

// TestGodocOnAllExports (CLI-4): every exported identifier is documented.
func TestGodocOnAllExports(t *testing.T) {
	for _, dir := range []string{".", "clienttest"} {
		pkg := parse(t, dir)
		for fname, f := range pkg.Files {
			for _, d := range f.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					if d.Name.IsExported() && exportedRecv(d) && d.Doc == nil {
						t.Errorf("%s: func %s has no godoc", fname, d.Name.Name)
					}
				case *ast.GenDecl:
					for _, s := range d.Specs {
						switch s := s.(type) {
						case *ast.TypeSpec:
							if s.Name.IsExported() && d.Doc == nil && s.Doc == nil {
								t.Errorf("%s: type %s has no godoc", fname, s.Name.Name)
							}
						case *ast.ValueSpec:
							for _, n := range s.Names {
								if n.IsExported() && d.Doc == nil && s.Doc == nil && s.Comment == nil {
									t.Errorf("%s: %s has no godoc", fname, n.Name)
								}
							}
						}
					}
				}
			}
		}
		if pkg.Doc == "" {
			t.Errorf("package in %s has no package comment", dir)
		}
	}
}

type pkgInfo struct {
	Files map[string]*ast.File
	Doc   string
}

func parse(t *testing.T, dir string) pkgInfo {
	t.Helper()
	fset := token.NewFileSet()
	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	out := pkgInfo{Files: map[string]*ast.File{}}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		out.Files[f] = af
		if af.Doc != nil {
			out.Doc += af.Doc.Text()
		}
	}
	return out
}

func exportedRecv(d *ast.FuncDecl) bool {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return true
	}
	e := d.Recv.List[0].Type
	if s, ok := e.(*ast.StarExpr); ok {
		e = s.X
	}
	id, ok := e.(*ast.Ident)
	return ok && id.IsExported()
}

func render(fset *token.FileSet, n any) string {
	var b bytes.Buffer
	_ = printer.Fprint(&b, fset, n)
	return strings.Join(strings.Fields(b.String()), " ")
}

func exported(t *testing.T, dir string) []string {
	t.Helper()
	fset := token.NewFileSet()
	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	pkgName := "client"
	if dir != "." {
		pkgName = "clienttest"
	}
	var out []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if !d.Name.IsExported() || !exportedRecv(d) {
					continue
				}
				d.Body, d.Doc = nil, nil
				out = append(out, pkgName+": "+render(fset, d))
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.TypeSpec:
						if !s.Name.IsExported() {
							continue
						}
						s.Doc, s.Comment = nil, nil
						stripFields(s.Type)
						out = append(out, pkgName+": type "+render(fset, s))
					case *ast.ValueSpec:
						for i, n := range s.Names {
							if !n.IsExported() {
								continue
							}
							line := d.Tok.String() + " " + n.Name
							if s.Type != nil {
								line += " " + render(fset, s.Type)
							}
							if i < len(s.Values) {
								line += " = " + render(fset, s.Values[i])
							}
							out = append(out, pkgName+": "+line)
						}
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// stripFields drops comments and unexported fields so only the exported shape
// is compared.
func stripFields(e ast.Expr) {
	st, ok := e.(*ast.StructType)
	if !ok {
		return
	}
	var keep []*ast.Field
	for _, f := range st.Fields.List {
		f.Doc, f.Comment = nil, nil
		if len(f.Names) == 0 {
			continue
		}
		var names []*ast.Ident
		for _, n := range f.Names {
			if n.IsExported() {
				names = append(names, n)
			}
		}
		if len(names) > 0 {
			f.Names = names
			keep = append(keep, f)
		}
	}
	st.Fields.List = keep
}
