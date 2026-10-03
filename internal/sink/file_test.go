package sink

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

var ctx = context.Background()

func spec(t *testing.T, name string, mode fs.FileMode) domain.SinkSpec {
	t.Helper()
	return domain.SinkSpec{Path: filepath.Join(t.TempDir(), name), Mode: mode}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWriteModeAndContent(t *testing.T) {
	for _, tc := range []struct {
		fmt  domain.SinkFormat
		want string
	}{{"", "tok"}, {domain.SinkRaw, "tok"}, {domain.SinkRawNL, "tok\n"}} {
		sp := spec(t, "cred", 0o440)
		sp.Format = tc.fmt
		if err := New().Write(ctx, sp, domain.NewSecret("tok")); err != nil {
			t.Fatal(err)
		}
		if got := read(t, sp.Path); got != tc.want {
			t.Errorf("format %q: got %q want %q", tc.fmt, got, tc.want)
		}
		st, _ := os.Stat(sp.Path)
		if st.Mode().Perm() != 0o440 {
			t.Errorf("mode %v", st.Mode().Perm())
		}
	}
}

func TestWriteReplacesAtomicallyAndLeavesNoTemp(t *testing.T) {
	sp := spec(t, "cred", 0o400)
	s := New()
	_ = s.Write(ctx, sp, domain.NewSecret("one"))
	if err := s.Write(ctx, sp, domain.NewSecret("two")); err != nil {
		t.Fatal(err)
	}
	if read(t, sp.Path) != "two" {
		t.Fatal("not replaced")
	}
	ents, _ := os.ReadDir(filepath.Dir(sp.Path))
	if len(ents) != 1 {
		t.Fatalf("leftover files: %v", ents)
	}
}

func TestWriteCreatesParentDir(t *testing.T) {
	sp := spec(t, "a/b/cred", 0o440)
	if err := New().Write(ctx, sp, domain.NewSecret("x")); err != nil {
		t.Fatal(err)
	}
}

// AC-007: failure between temp write and rename leaves the old target intact
// and no temp file.
func TestRenameFailureKeepsOldTarget(t *testing.T) {
	sp := spec(t, "cred", 0o440)
	s := New()
	_ = s.Write(ctx, sp, domain.NewSecret("old"))
	s.rename = func(string, string) error { return errors.New("boom") }
	err := s.Write(ctx, sp, domain.NewSecret("new-secret-value"))
	if err == nil || strings.Contains(err.Error(), "new-secret-value") {
		t.Fatalf("err = %v", err)
	}
	if read(t, sp.Path) != "old" {
		t.Fatal("target changed")
	}
	ents, _ := os.ReadDir(filepath.Dir(sp.Path))
	if len(ents) != 1 {
		t.Fatalf("temp left: %v", ents)
	}
}

func TestRenameFailureNoTargetMeansNoFile(t *testing.T) {
	sp := spec(t, "cred", 0o440)
	s := New()
	s.rename = func(string, string) error { return errors.New("boom") }
	_ = s.Write(ctx, sp, domain.NewSecret("v"))
	if _, err := os.Stat(sp.Path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("partial target exists: %v", err)
	}
}

func TestValidation(t *testing.T) {
	s := New()
	d := t.TempDir()
	cases := []struct {
		name string
		sp   domain.SinkSpec
		want error
	}{
		{"relative", domain.SinkSpec{Path: "rel", Mode: 0o440}, domain.ErrConfig},
		{"zero mode", domain.SinkSpec{Path: d + "/x"}, domain.ErrConfig},
		{"setuid", domain.SinkSpec{Path: d + "/x", Mode: fs.ModeSetuid | 0o440}, domain.ErrConfig},
		{"world writable", domain.SinkSpec{Path: d + "/x", Mode: 0o666}, domain.ErrPolicy},
		{"bad format", domain.SinkSpec{Path: d + "/x", Mode: 0o440, Format: "json"}, domain.ErrConfig},
		{"bad owner", domain.SinkSpec{Path: d + "/x", Mode: 0o440, Owner: "no-such-user-zz9"}, domain.ErrConfig},
		{"bad group", domain.SinkSpec{Path: d + "/x", Mode: 0o440, Group: "no-such-group-zz9"}, domain.ErrConfig},
	}
	for _, tc := range cases {
		err := s.Write(ctx, tc.sp, domain.NewSecret("v"))
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v want %v", tc.name, err, tc.want)
		}
	}
	if err := s.Remove(ctx, domain.SinkSpec{Path: "rel"}); !errors.Is(err, domain.ErrConfig) {
		t.Errorf("remove relative: %v", err)
	}
}

func TestOwnerGroupCurrentUser(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skip(err)
	}
	sp := spec(t, "cred", 0o440)
	sp.Owner, sp.Group = u.Username, g.Name
	if err := New().Write(ctx, sp, domain.NewSecret("v")); err != nil {
		t.Fatal(err)
	}
}

func TestChownFailureAndNonNumericIDs(t *testing.T) {
	s := New()
	s.lookupUser = func(string) (*user.User, error) { return &user.User{Uid: "7"}, nil }
	s.chown = func(*os.File, int, int) error { return errors.New("eperm") }
	sp := spec(t, "cred", 0o440)
	sp.Owner = "x"
	if err := s.Write(ctx, sp, domain.NewSecret("v")); err == nil {
		t.Fatal("want chown error")
	}
	if _, err := os.Stat(sp.Path); err == nil {
		t.Fatal("target created despite chown failure")
	}
	s.lookupUser = func(string) (*user.User, error) { return &user.User{Uid: "abc"}, nil }
	if err := s.Write(ctx, sp, domain.NewSecret("v")); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("uid: %v", err)
	}
	s.lookupGrp = func(string) (*user.Group, error) { return &user.Group{Gid: "abc"}, nil }
	sp.Owner, sp.Group = "", "g"
	if err := s.Write(ctx, sp, domain.NewSecret("v")); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("gid: %v", err)
	}
}

func TestContextCancelled(t *testing.T) {
	c, cancel := context.WithCancel(ctx)
	cancel()
	sp := spec(t, "cred", 0o440)
	s := New()
	if err := s.Write(c, sp, domain.NewSecret("v")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := s.Remove(c, sp); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestRemoveMissingIsOK(t *testing.T) {
	sp := spec(t, "cred", 0o440)
	s := New()
	if err := s.Remove(ctx, sp); err != nil {
		t.Fatal(err)
	}
	_ = s.Write(ctx, sp, domain.NewSecret("v"))
	if err := s.Remove(ctx, sp); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sp.Path); err == nil {
		t.Fatal("still exists")
	}
}

func TestWipeStaleRemovesSinksAndOrphanTemps(t *testing.T) {
	dir := t.TempDir()
	a := domain.SinkSpec{Path: filepath.Join(dir, "a[1]"), Mode: 0o440}
	b := domain.SinkSpec{Path: filepath.Join(dir, "b"), Mode: 0o440}
	for _, p := range []string{a.Path, b.Path, filepath.Join(dir, ".a[1]"+tempMarker+"deadbeef"), filepath.Join(dir, "unrelated")} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := New().WipeStale(ctx, []domain.SinkSpec{a, b}); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 || ents[0].Name() != "unrelated" {
		t.Fatalf("remaining: %v", ents)
	}
	if err := New().RemoveAll(ctx, []domain.SinkSpec{a}); err != nil {
		t.Fatal(err)
	}
}

func TestWipeStaleReportsErrors(t *testing.T) {
	err := New().WipeStale(ctx, []domain.SinkSpec{{Path: "rel"}})
	if !errors.Is(err, domain.ErrConfig) {
		t.Fatal(err)
	}
}

func TestWriteDirIsFileFails(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "f")
	_ = os.WriteFile(f, nil, 0o600)
	err := New().Write(ctx, domain.SinkSpec{Path: filepath.Join(f, "x"), Mode: 0o440}, domain.NewSecret("v"))
	if err == nil {
		t.Fatal("want error")
	}
}

func TestWriteOverNonEmptyDirFailsCleanly(t *testing.T) {
	sp := spec(t, "cred", 0o440)
	_ = os.MkdirAll(filepath.Join(sp.Path, "child"), 0o750)
	if err := New().Write(ctx, sp, domain.NewSecret("v")); err == nil {
		t.Fatal("want rename error")
	}
	ents, _ := os.ReadDir(filepath.Dir(sp.Path))
	if len(ents) != 1 {
		t.Fatalf("temp left: %v", ents)
	}
	if err := New().Remove(ctx, sp); err == nil {
		t.Fatal("remove of non-empty dir should error")
	}
	if err := New().WipeStale(ctx, []domain.SinkSpec{sp}); err == nil {
		t.Fatal("wipe should report error")
	}
}

func TestReadOnlyDirFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores dir modes")
	}
	d := t.TempDir()
	_ = os.Chmod(d, 0o500)
	t.Cleanup(func() { _ = os.Chmod(d, 0o700) })
	if err := New().Write(ctx, domain.SinkSpec{Path: filepath.Join(d, "c"), Mode: 0o440}, domain.NewSecret("v")); err == nil {
		t.Fatal("want error")
	}
}

func TestSyncDirMissing(t *testing.T) {
	if err := syncDir(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("want error")
	}
}
