package encfile

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/store/storetest"
)

type fixedKey struct {
	key []byte
	err error
}

func (f fixedKey) Key(context.Context) ([]byte, error) { return f.key, f.err }

var key32 = bytes.Repeat([]byte{7}, 32)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sub", "store.enc")
	s, err := New(p, fixedKey{key: key32})
	if err != nil {
		t.Fatal(err)
	}
	return s, p
}

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) domain.SecretStore { s, _ := newStore(t); return s })
}

func TestConformanceTwoInstancesShareFile(t *testing.T) {
	// Separate Store values on one file model two writers (cross-process flock).
	storetest.Run(t, func(t *testing.T) domain.SecretStore {
		p := filepath.Join(t.TempDir(), "s.enc")
		a, _ := New(p, fixedKey{key: key32})
		b, _ := New(p, fixedKey{key: key32})
		return &alternating{a: a, b: b}
	})
}

type alternating struct {
	a, b *Store
	n    atomic.Int64
}

func (x *alternating) pick() *Store {
	if x.n.Add(1)%2 == 0 {
		return x.a
	}
	return x.b
}
func (x *alternating) Get(ctx context.Context, k string) (domain.SecretValue, error) {
	return x.pick().Get(ctx, k)
}
func (x *alternating) Put(ctx context.Context, k string, v domain.SecretString, e string) (string, error) {
	return x.pick().Put(ctx, k, v, e)
}

func TestFileIsEncryptedAndPrivate(t *testing.T) {
	s, p := newStore(t)
	ctx := context.Background()
	if _, err := s.Put(ctx, "gh", domain.NewSecret("ghp_PLAINTEXT_TOKEN"), ""); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("ghp_PLAINTEXT_TOKEN")) || bytes.Contains(raw, []byte("gh")) && bytes.Contains(raw, []byte(`"gh"`)) {
		t.Fatal("file holds plaintext")
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", st.Mode().Perm())
	}
	ds, _ := os.Stat(filepath.Dir(p))
	if ds.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %v", ds.Mode().Perm())
	}
}

func TestPersistsAcrossInstances(t *testing.T) {
	s, p := newStore(t)
	ctx := context.Background()
	v, _ := s.Put(ctx, "k", domain.NewSecret("val"), "")
	s2, _ := New(p, fixedKey{key: key32})
	got, err := s2.Get(ctx, "k")
	if err != nil || got.Value.Reveal() != "val" || got.Version != v {
		t.Fatalf("got %v %v", got, err)
	}
}

func TestWrongKeyFailsClosed(t *testing.T) {
	s, p := newStore(t)
	ctx := context.Background()
	_, _ = s.Put(ctx, "k", domain.NewSecret("val"), "")
	other, _ := New(p, fixedKey{key: bytes.Repeat([]byte{9}, 32)})
	if _, err := other.Get(ctx, "k"); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("err = %v", err)
	}
	if _, err := other.Put(ctx, "k", domain.NewSecret("x"), ""); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("put err = %v (must not overwrite)", err)
	}
	// original still readable
	if got, err := s.Get(ctx, "k"); err != nil || got.Value.Reveal() != "val" {
		t.Fatalf("original damaged: %v %v", got, err)
	}
}

func TestTamperedAndTruncatedFiles(t *testing.T) {
	s, p := newStore(t)
	ctx := context.Background()
	_, _ = s.Put(ctx, "k", domain.NewSecret("val"), "")
	raw, _ := os.ReadFile(p)
	for name, mod := range map[string][]byte{
		"flipped":   append(append([]byte{}, raw[:len(raw)-1]...), raw[len(raw)-1]^1),
		"truncated": raw[:10],
		"badmagic":  append([]byte("XXXXX"), raw[5:]...),
		"empty":     {},
	} {
		if err := os.WriteFile(p, mod, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get(ctx, "k"); !errors.Is(err, domain.ErrProvider) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
}

func TestWorldReadableFileRefused(t *testing.T) {
	s, p := newStore(t)
	ctx := context.Background()
	_, _ = s.Put(ctx, "k", domain.NewSecret("val"), "")
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "k"); !errors.Is(err, domain.ErrPolicy) {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.Put(ctx, "k", domain.NewSecret("x"), "bogus"); !errors.Is(err, domain.ErrPolicy) {
		t.Fatalf("put err = %v", err)
	}
}

func TestKeyProviderProblems(t *testing.T) {
	ctx := context.Background()
	p := filepath.Join(t.TempDir(), "s.enc")
	boom := errors.New("signer down")
	s, _ := New(p, fixedKey{err: boom})
	if _, err := s.Put(ctx, "k", domain.NewSecret("v"), ""); !errors.Is(err, domain.ErrProvider) || !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	s, _ = New(p, fixedKey{key: []byte("short")})
	if _, err := s.Put(ctx, "k", domain.NewSecret("v"), ""); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("err = %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New("", fixedKey{key: key32}); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("err = %v", err)
	}
	if _, err := New("/x", nil); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("err = %v", err)
	}
	s, _ := newStore(t)
	if _, err := s.Get(context.Background(), ""); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("err = %v", err)
	}
	if _, err := s.Put(context.Background(), "", domain.NewSecret("v"), ""); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("err = %v", err)
	}
}

func TestIOErrors(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	// parent is a regular file: cannot create directory
	f := filepath.Join(dir, "file")
	_ = os.WriteFile(f, nil, 0o600)
	s, _ := New(filepath.Join(f, "x", "s.enc"), fixedKey{key: key32})
	if _, err := s.Put(ctx, "k", domain.NewSecret("v"), ""); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("err = %v", err)
	}
	// path is a directory: read fails
	d := filepath.Join(dir, "d.enc")
	_ = os.Mkdir(d, 0o700)
	s, _ = New(d, fixedKey{key: key32})
	if _, err := s.Get(ctx, "k"); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("err = %v", err)
	}
}

func TestCanceledContext(t *testing.T) {
	s, _ := newStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Get(ctx, "k"); err == nil {
		t.Fatal("want error")
	}
}

func TestNoTempFilesLeft(t *testing.T) {
	s, p := newStore(t)
	for i := range 3 {
		v := ""
		if i > 0 {
			g, _ := s.Get(context.Background(), "k")
			v = g.Version
		}
		if _, err := s.Put(context.Background(), "k", domain.NewSecret("v"), v); err != nil {
			t.Fatal(err)
		}
	}
	ents, _ := os.ReadDir(filepath.Dir(p))
	for _, e := range ents {
		if e.Name() != "store.enc" && e.Name() != "store.enc.lock" {
			t.Fatalf("stray file %s", e.Name())
		}
	}
}

func TestMalformedPayloadFailsClosed(t *testing.T) {
	s, p := newStore(t)
	// Build a validly authenticated file whose plaintext is not JSON.
	salt := bytes.Repeat([]byte{1}, saltLen)
	nonce := bytes.Repeat([]byte{2}, nonceLen)
	k, err := s.dataKey(context.Background(), salt)
	if err != nil {
		t.Fatal(err)
	}
	out := append(append(append([]byte{}, magic...), salt...), nonce...)
	out = newGCM(k).Seal(out, nonce, []byte("not json"), magic)
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(context.Background(), "k"); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("err = %v", err)
	}
}

func TestReadOnlyDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory modes")
	}
	s, p := newStore(t)
	ctx := context.Background()
	if _, err := s.Put(ctx, "k", domain.NewSecret("v"), ""); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(p)
	_ = os.Chmod(dir, 0o500) // lock file exists, but temp file cannot be created
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	g, _ := s.Get(ctx, "k")
	if _, err := s.Put(ctx, "k", domain.NewSecret("w"), g.Version); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("err = %v", err)
	}
	if got, _ := s.Get(ctx, "k"); got.Value.Reveal() != "v" {
		t.Fatal("value changed")
	}
	_ = os.Chmod(dir, 0o700)
	_ = os.Remove(p + ".lock")
	_ = os.Chmod(dir, 0o500)
	if _, err := s.Get(ctx, "k"); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("lock err = %v", err)
	}
}
