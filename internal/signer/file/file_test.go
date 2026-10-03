package file_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/signer/file"
)

var _ domain.Signer = (*file.Signer)(nil)

func writeKey(t *testing.T, blockType string, der []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pkcs8(t *testing.T, k crypto.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRS256SignVerifies(t *testing.T) {
	k := rsaKey(t)
	p := writeKey(t, "PRIVATE KEY", pkcs8(t, k), 0o600)
	s, err := file.New(file.Config{Path: p, KID: "kid-1"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Alg() != "RS256" {
		t.Fatalf("alg %s", s.Alg())
	}
	in := []byte("header.payload")
	sig, kid, err := s.Sign(context.Background(), "RS256", in)
	if err != nil || kid != "kid-1" {
		t.Fatalf("sign: %v kid=%s", err, kid)
	}
	h := sha256.Sum256(in)
	if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, h[:], sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestPKCS1RSAAccepted(t *testing.T) {
	k := rsaKey(t)
	p := writeKey(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(k), 0o600)
	if _, err := file.New(file.Config{Path: p, KID: "k"}); err != nil {
		t.Fatal(err)
	}
}

// ASSUMPTION(A-01): ES256 is accepted by Okta; the signer supports it but it is flagged.
func TestES256A01SignRawRS(t *testing.T) {
	k := ecKey(t)
	p := writeKey(t, "PRIVATE KEY", pkcs8(t, k), 0o600)
	s, err := file.New(file.Config{Path: p, KID: "e1"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Alg() != "ES256" {
		t.Fatalf("alg %s", s.Alg())
	}
	in := []byte("a.b")
	sig, _, err := s.Sign(context.Background(), "ES256", in)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Fatalf("sig len %d", len(sig))
	}
	h := sha256.Sum256(in)
	r, ss := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&k.PublicKey, h[:], r, ss) {
		t.Fatal("ecdsa verify failed")
	}
}

func TestSECGECKeyAccepted(t *testing.T) {
	k := ecKey(t)
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	p := writeKey(t, "EC PRIVATE KEY", der, 0o600)
	if _, err := file.New(file.Config{Path: p, KID: "k"}); err != nil {
		t.Fatal(err)
	}
}

func TestAlgMismatchRejected(t *testing.T) {
	p := writeKey(t, "PRIVATE KEY", pkcs8(t, rsaKey(t)), 0o600)
	s, _ := file.New(file.Config{Path: p, KID: "k"})
	if _, _, err := s.Sign(context.Background(), "ES256", []byte("x")); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("want ErrConfig, got %v", err)
	}
	if _, _, err := s.Sign(context.Background(), "HS256", []byte("x")); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("want ErrConfig, got %v", err)
	}
}

func TestRefusesAccessibleKeyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	for _, mode := range []os.FileMode{0o644, 0o604, 0o640, 0o660, 0o666} {
		p := writeKey(t, "PRIVATE KEY", pkcs8(t, rsaKey(t)), mode)
		_, err := file.New(file.Config{Path: p, KID: "k"})
		if !errors.Is(err, domain.ErrPolicy) {
			t.Errorf("mode %o: want ErrPolicy, got %v", mode, err)
		}
	}
	p := writeKey(t, "PRIVATE KEY", pkcs8(t, rsaKey(t)), 0o400)
	if _, err := file.New(file.Config{Path: p, KID: "k"}); err != nil {
		t.Errorf("0400 must be accepted: %v", err)
	}
}

func TestConfigErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	_ = os.WriteFile(bad, []byte("not pem"), 0o600)
	garbage := filepath.Join(dir, "garbage.pem")
	_ = os.WriteFile(garbage, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("zzz")}), 0o600)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384path := writeKey(t, "PRIVATE KEY", pkcs8(t, p384), 0o600)
	cases := map[string]file.Config{
		"empty path":  {KID: "k"},
		"missing kid": {Path: bad},
		"missing":     {Path: filepath.Join(dir, "nope"), KID: "k"},
		"not pem":     {Path: bad, KID: "k"},
		"bad der":     {Path: garbage, KID: "k"},
		"directory":   {Path: dir, KID: "k"},
		"p384":        {Path: p384path, KID: "k"},
	}
	for name, c := range cases {
		if _, err := file.New(c); !errors.Is(err, domain.ErrConfig) {
			t.Errorf("%s: want ErrConfig, got %v", name, err)
		}
	}
}

func TestRSAKeyTooSmallRejected(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 1024)
	p := writeKey(t, "PRIVATE KEY", pkcs8(t, k), 0o600)
	if _, err := file.New(file.Config{Path: p, KID: "k"}); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("want ErrConfig, got %v", err)
	}
}

func TestPublicJWKRSA(t *testing.T) {
	k := rsaKey(t)
	s, _ := file.New(file.Config{Path: writeKey(t, "PRIVATE KEY", pkcs8(t, k), 0o600), KID: "kid-r"})
	raw, err := s.Public()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["kty"] != "RSA" || m["kid"] != "kid-r" || m["alg"] != "RS256" || m["use"] != "sig" {
		t.Fatalf("jwk %v", m)
	}
	n, _ := base64.RawURLEncoding.DecodeString(m["n"])
	if new(big.Int).SetBytes(n).Cmp(k.N) != 0 {
		t.Fatal("n mismatch")
	}
	if _, ok := m["d"]; ok {
		t.Fatal("private material in JWK")
	}
	for _, f := range []string{"p", "q", "dp", "dq", "qi"} {
		if _, ok := m[f]; ok {
			t.Fatalf("private field %s", f)
		}
	}
}

func TestPublicJWKEC(t *testing.T) {
	k := ecKey(t)
	s, _ := file.New(file.Config{Path: writeKey(t, "PRIVATE KEY", pkcs8(t, k), 0o600), KID: "kid-e"})
	raw, _ := s.Public()
	var m map[string]string
	_ = json.Unmarshal(raw, &m)
	if m["kty"] != "EC" || m["crv"] != "P-256" || m["alg"] != "ES256" {
		t.Fatalf("jwk %v", m)
	}
	x, _ := base64.RawURLEncoding.DecodeString(m["x"])
	y, _ := base64.RawURLEncoding.DecodeString(m["y"])
	if len(x) != 32 || len(y) != 32 || new(big.Int).SetBytes(x).Cmp(k.X) != 0 || new(big.Int).SetBytes(y).Cmp(k.Y) != 0 {
		t.Fatal("coordinate mismatch")
	}
	if _, ok := m["d"]; ok {
		t.Fatal("private material in JWK")
	}
}

func TestSignHonoursCancelledContext(t *testing.T) {
	s, _ := file.New(file.Config{Path: writeKey(t, "PRIVATE KEY", pkcs8(t, rsaKey(t)), 0o600), KID: "k"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.Sign(ctx, "RS256", []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestErrorsDoNotLeakKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k.pem")
	_ = os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("SECRETBYTES")}), 0o600)
	_, err := file.New(file.Config{Path: p, KID: "k"})
	if err == nil {
		t.Fatal("want error")
	}
	if s := err.Error(); containsAny(s, "SECRETBYTES", "U0VDUkVUQllURVM") {
		t.Fatalf("leak: %s", s)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		for i := 0; i+len(x) <= len(s); i++ {
			if s[i:i+len(x)] == x {
				return true
			}
		}
	}
	return false
}

func TestUnreadableKeyFileIsConfigError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read anything")
	}
	p := writeKey(t, "PRIVATE KEY", pkcs8(t, rsaKey(t)), 0o000)
	if _, err := file.New(file.Config{Path: p, KID: "k"}); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("got %v", err)
	}
}

func TestKIDAccessor(t *testing.T) {
	s, _ := file.New(file.Config{Path: writeKey(t, "PRIVATE KEY", pkcs8(t, rsaKey(t)), 0o600), KID: "kk"})
	if s.KID() != "kk" {
		t.Fatal(s.KID())
	}
	jwk, _ := s.Public()
	jwk[0] = 'X' // callers cannot corrupt the signer's copy
	again, _ := s.Public()
	if again[0] != '{' {
		t.Fatal("Public must return a copy")
	}
}

func TestUnsupportedKeyTypeEd25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := writeKey(t, "PRIVATE KEY", pkcs8(t, priv), 0o600)
	if _, err := file.New(file.Config{Path: p, KID: "k"}); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("got %v", err)
	}
}
