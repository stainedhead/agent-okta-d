// Package sink implements domain.Sink: atomic credential files (FR-8).
package sink

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

const (
	tempPrefix = "."
	tempMarker = ".okta-d-tmp-"
)

// File writes credential files atomically: a 0600 temp file in the target
// directory is written, chowned, chmodded to the configured mode, fsynced and
// renamed over the target, then the directory is fsynced. A crash at any point
// leaves either the old file or the new file, never a partial target; orphan
// temp files are removed by WipeStale at the next start.
type File struct {
	rename     func(oldpath, newpath string) error
	lookupUser func(name string) (*user.User, error)
	lookupGrp  func(name string) (*user.Group, error)
	chown      func(f *os.File, uid, gid int) error
}

var _ domain.Sink = (*File)(nil)

// New returns a File sink using the real filesystem.
func New() *File {
	return &File{
		rename:     os.Rename,
		lookupUser: user.Lookup,
		lookupGrp:  user.LookupGroup,
		chown:      func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) },
	}
}

func validate(spec domain.SinkSpec) error {
	if !filepath.IsAbs(spec.Path) {
		return fmt.Errorf("%w: sink path %q must be absolute", domain.ErrConfig, spec.Path)
	}
	if spec.Mode == 0 || spec.Mode&^fs.FileMode(0o777) != 0 {
		return fmt.Errorf("%w: sink %q has invalid mode %v", domain.ErrConfig, spec.Path, spec.Mode)
	}
	if spec.Mode&0o002 != 0 {
		return fmt.Errorf("%w: sink %q mode %v is world-writable", domain.ErrPolicy, spec.Path, spec.Mode)
	}
	switch spec.Format {
	case "", domain.SinkRaw, domain.SinkRawNL:
	default:
		return fmt.Errorf("%w: sink %q unknown format %q", domain.ErrConfig, spec.Path, spec.Format)
	}
	return nil
}

func (s *File) ids(spec domain.SinkSpec) (uid, gid int, err error) {
	uid, gid = -1, -1
	if spec.Owner != "" {
		u, e := s.lookupUser(spec.Owner)
		if e != nil {
			return 0, 0, fmt.Errorf("%w: sink owner %q: %v", domain.ErrConfig, spec.Owner, e)
		}
		if uid, e = strconv.Atoi(u.Uid); e != nil {
			return 0, 0, fmt.Errorf("%w: sink owner %q has non-numeric uid", domain.ErrConfig, spec.Owner)
		}
	}
	if spec.Group != "" {
		g, e := s.lookupGrp(spec.Group)
		if e != nil {
			return 0, 0, fmt.Errorf("%w: sink group %q: %v", domain.ErrConfig, spec.Group, e)
		}
		if gid, e = strconv.Atoi(g.Gid); e != nil {
			return 0, 0, fmt.Errorf("%w: sink group %q has non-numeric gid", domain.ErrConfig, spec.Group)
		}
	}
	return uid, gid, nil
}

// Write implements domain.Sink. The content is never included in an error.
func (s *File) Write(ctx context.Context, spec domain.SinkSpec, content domain.SecretString) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validate(spec); err != nil {
		return err
	}
	uid, gid, err := s.ids(spec)
	if err != nil {
		return err
	}
	dir := filepath.Dir(spec.Path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("sink: create dir: %w", err)
	}
	f, err := createTemp(dir, filepath.Base(spec.Path))
	if err != nil {
		return fmt.Errorf("sink: create temp: %w", err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	data := []byte(content.Reveal())
	if spec.Format == domain.SinkRawNL {
		data = append(data, '\n')
	}
	if _, err = f.Write(data); err != nil {
		return fmt.Errorf("sink: write temp: %w", err)
	}
	if uid != -1 || gid != -1 {
		if err = s.chown(f, uid, gid); err != nil {
			return fmt.Errorf("sink: chown: %w", err)
		}
	}
	if err = f.Chmod(spec.Mode); err != nil {
		return fmt.Errorf("sink: chmod: %w", err)
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("sink: fsync: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("sink: close: %w", err)
	}
	if err = s.rename(tmp, spec.Path); err != nil {
		return fmt.Errorf("sink: rename: %w", err)
	}
	return syncDir(dir)
}

// Remove implements domain.Sink; a missing file is not an error.
func (s *File) Remove(ctx context.Context, spec domain.SinkSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !filepath.IsAbs(spec.Path) {
		return fmt.Errorf("%w: sink path %q must be absolute", domain.ErrConfig, spec.Path)
	}
	if err := os.Remove(spec.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("sink: remove: %w", err)
	}
	return nil
}

// WipeStale removes every sink file, and any orphan temp file next to it,
// left by a previous run (SIGKILL). Call it at start. All specs are attempted;
// the joined error reports failures.
func (s *File) WipeStale(ctx context.Context, specs []domain.SinkSpec) error {
	var errs []error
	for _, spec := range specs {
		if err := s.Remove(ctx, spec); err != nil {
			errs = append(errs, err)
			continue
		}
		pattern := filepath.Join(filepath.Dir(spec.Path), tempPrefix+filepath.Base(spec.Path)+tempMarker+"*")
		matches, _ := filepath.Glob(escapeGlob(pattern))
		for _, m := range matches {
			if err := os.Remove(m); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, fmt.Errorf("sink: remove stale temp: %w", err))
			}
		}
	}
	return errors.Join(errs...)
}

// RemoveAll removes every sink (stop and revoke paths). Same semantics as
// WipeStale; kept separate for call-site clarity.
func (s *File) RemoveAll(ctx context.Context, specs []domain.SinkSpec) error {
	return s.WipeStale(ctx, specs)
}

func escapeGlob(p string) string {
	// keep the trailing "*" wildcard, escape meta characters elsewhere
	body := strings.TrimSuffix(p, "*")
	r := strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`)
	return r.Replace(body) + "*"
}

func createTemp(dir, base string) (*os.File, error) {
	for range 10 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		name := filepath.Join(dir, tempPrefix+base+tempMarker+hex.EncodeToString(b[:]))
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return f, err
	}
	return nil, errors.New("could not create unique temp file")
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("sink: open dir: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sink: fsync dir: %w", err)
	}
	return nil
}
