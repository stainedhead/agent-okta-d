package keychain

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"runtime"
	"testing"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

type fakeBackend struct {
	ec  *ecdsa.PrivateKey
	rsa *rsa.PrivateKey
	err error
}

func (f fakeBackend) Public() (crypto.PublicKey, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.ec != nil {
		return &f.ec.PublicKey, nil
	}
	return &f.rsa.PublicKey, nil
}

func (f fakeBackend) SignDigest(_ context.Context, alg string, d []byte) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	if alg == "ES256" {
		return ecdsa.SignASN1(rand.Reader, f.ec, d)
	}
	return rsa.SignPKCS1v15(rand.Reader, f.rsa, crypto.SHA256, d)
}

func TestNew_NilBackend(t *testing.T) {
	if _, err := New(nil, "k"); !errors.Is(err, domain.ErrConfig) {
		t.Fatal(err)
	}
}

func TestSignES256AndPublic(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, err := New(fakeBackend{ec: ec}, "kid")
	if err != nil {
		t.Fatal(err)
	}
	in := []byte("h.p")
	sig, kid, err := s.Sign(context.Background(), "ES256", in)
	if err != nil || kid != "kid" || len(sig) != 64 {
		t.Fatalf("%v %q %d", err, kid, len(sig))
	}
	d := sha256.Sum256(in)
	if !ecdsa.Verify(&ec.PublicKey, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("bad signature")
	}
	j, err := s.Public()
	var m map[string]string
	if err != nil || json.Unmarshal(j, &m) != nil || m["kty"] != "EC" {
		t.Fatalf("%v %s", err, j)
	}
}

func TestSignRS256AndErrors(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	s, _ := New(fakeBackend{rsa: rk}, "kid")
	in := []byte("h.p")
	sig, _, err := s.Sign(context.Background(), "RS256", in)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(in)
	if rsa.VerifyPKCS1v15(&rk.PublicKey, crypto.SHA256, d[:], sig) != nil {
		t.Fatal("bad rsa signature")
	}
	bad, _ := New(fakeBackend{err: errors.New("device locked")}, "kid")
	if _, _, err := bad.Sign(context.Background(), "RS256", in); !errors.Is(err, domain.ErrTransient) {
		t.Fatal(err)
	}
	if _, err := bad.Public(); err == nil {
		t.Fatal("expected public error")
	}
}

func TestOpen_PlatformGate(t *testing.T) {
	b, err := Open("ref")
	if b != nil || !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("Open must return ErrConfig, got %v", err)
	}
	if Supported != (runtime.GOOS == "darwin") {
		t.Fatalf("Supported=%v on %s", Supported, runtime.GOOS)
	}
}
