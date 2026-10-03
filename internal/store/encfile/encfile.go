// Package encfile is the file-encrypted SecretStore (PRD MG-3, FR-18): one
// AES-256-GCM file holding every key, whose data key comes from the configured
// signer through KeyProvider. Unix only (flock); all three release targets are
// unix.
package encfile

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

var magic = []byte("AODE1")

const (
	saltLen  = 16
	nonceLen = 12
	keyLen   = 32
	hkdfInfo = "agent-okta-d encfile v1"
)

// KeyProvider yields the secret key material the data key is derived from
// (for example a deterministic signature over a fixed label made by the
// configured signer, so the key never rests on disk). It must return at least
// 32 bytes and the same value on every call.
type KeyProvider interface {
	Key(ctx context.Context) ([]byte, error)
}

// Store implements domain.SecretStore over one encrypted file.
type Store struct {
	path string
	kp   KeyProvider
	mu   sync.Mutex // serialises in-process; flock covers other processes
}

var _ domain.SecretStore = (*Store)(nil)

// New returns a Store on path. The file and its directory are created lazily
// with modes 0600 and 0700.
func New(path string, kp KeyProvider) (*Store, error) {
	if path == "" {
		return nil, domain.NewConfigError("store.path", "must not be empty")
	}
	if kp == nil {
		return nil, domain.NewConfigError("store.key_provider", "required")
	}
	return &Store{path: path, kp: kp}, nil
}

type entry struct {
	Value   string `json:"v"`
	Version uint64 `json:"n"`
}

func (s *Store) dataKey(ctx context.Context, salt []byte) ([]byte, error) {
	secret, err := s.kp.Key(ctx)
	if err != nil {
		return nil, domain.Wrap(domain.ErrProvider, fmt.Errorf("encfile key: %w", err))
	}
	if len(secret) < keyLen {
		return nil, domain.NewConfigError("store.key", "key material shorter than 32 bytes")
	}
	k, err := hkdf.Key(sha256.New, secret, salt, hkdfInfo, keyLen)
	if err != nil { // unreachable: keyLen is within the HKDF limit
		return nil, domain.Wrap(domain.ErrProvider, err)
	}
	return k, nil
}

// newGCM builds the AEAD. key is always keyLen bytes, so the AES and GCM
// constructors cannot fail.
func newGCM(key []byte) cipher.AEAD {
	b, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(b)
	return g
}

func ioErr(err error) error { return domain.Wrap(domain.ErrProvider, err) }

// lock takes the cross-process lock and returns its release func.
func (s *Store) lock(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return nil, ioErr(err)
	}
	f, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, ioErr(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, ioErr(err)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}

// load decrypts the file; a missing file is an empty store.
func (s *Store) load(ctx context.Context) (map[string]entry, error) {
	fi, err := os.Stat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]entry{}, nil
	}
	if err != nil {
		return nil, ioErr(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: store file %s is accessible to group or others", domain.ErrPolicy, s.path)
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return nil, ioErr(err)
	}
	hdr := len(magic) + saltLen + nonceLen
	if len(raw) < hdr || string(raw[:len(magic)]) != string(magic) {
		return nil, ioErr(errors.New("store file is not a valid encfile"))
	}
	salt := raw[len(magic) : len(magic)+saltLen]
	nonce := raw[len(magic)+saltLen : hdr]
	key, err := s.dataKey(ctx, salt)
	if err != nil {
		return nil, err
	}
	g := newGCM(key)
	pt, err := g.Open(nil, nonce, raw[hdr:], raw[:len(magic)])
	if err != nil {
		return nil, ioErr(errors.New("store file failed authentication (wrong key or tampered)"))
	}
	m := map[string]entry{}
	if err := json.Unmarshal(pt, &m); err != nil {
		return nil, ioErr(errors.New("store file payload malformed"))
	}
	return m, nil
}

// save encrypts and atomically replaces the file (temp, fsync, rename).
func (s *Store) save(ctx context.Context, m map[string]entry) error {
	pt, _ := json.Marshal(m) // map[string]entry always marshals
	salt := make([]byte, saltLen)
	nonce := make([]byte, nonceLen)
	// crypto/rand.Read never returns an error (it aborts the process instead).
	_, _ = rand.Read(salt)
	_, _ = rand.Read(nonce)
	key, err := s.dataKey(ctx, salt)
	if err != nil {
		return err
	}
	g := newGCM(key)
	out := append(append(append([]byte{}, magic...), salt...), nonce...)
	out = g.Seal(out, nonce, pt, magic)

	if err := writeAtomic(s.path, out); err != nil {
		return ioErr(err)
	}
	return nil
}

// writeAtomic replaces path with data via temp file, fsync and rename.
func writeAtomic(path string, data []byte) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".encfile-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(name)
		}
	}()
	if err = errors.Join(tmp.Chmod(0o600), writeSync(tmp, data)); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func writeSync(f *os.File, data []byte) error {
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

func checkKey(key string) error {
	if key == "" {
		return domain.NewConfigError("store.key", "must not be empty")
	}
	return nil
}

// Get implements domain.SecretStore.
func (s *Store) Get(ctx context.Context, key string) (domain.SecretValue, error) {
	if err := checkKey(key); err != nil {
		return domain.SecretValue{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lock(ctx)
	if err != nil {
		return domain.SecretValue{}, err
	}
	defer unlock()
	m, err := s.load(ctx)
	if err != nil {
		return domain.SecretValue{}, err
	}
	e, ok := m[key]
	if !ok {
		return domain.SecretValue{}, domain.ErrNotFound
	}
	return domain.SecretValue{Value: domain.NewSecret(e.Value), Version: strconv.FormatUint(e.Version, 10)}, nil
}

// Put implements domain.SecretStore. Versions are a per-key counter starting
// at 1; the check and the write happen under one exclusive lock.
func (s *Store) Put(ctx context.Context, key string, value domain.SecretString, expected string) (string, error) {
	if err := checkKey(key); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lock(ctx)
	if err != nil {
		return "", err
	}
	defer unlock()
	m, err := s.load(ctx)
	if err != nil {
		return "", err
	}
	cur, exists := m[key]
	switch {
	case !exists && expected != "":
		return "", domain.ErrVersionConflict
	case exists && expected != strconv.FormatUint(cur.Version, 10):
		return "", domain.ErrVersionConflict
	}
	next := cur.Version + 1
	m[key] = entry{Value: value.Reveal(), Version: next}
	if err := s.save(ctx, m); err != nil {
		return "", err
	}
	return strconv.FormatUint(next, 10), nil
}
