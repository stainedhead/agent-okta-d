package kms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

func TestDERToJOSE_Vectors(t *testing.T) {
	h := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	pad := func(n int, b byte) string { // n bytes of b as hex
		out := ""
		for i := 0; i < n; i++ {
			out += hex.EncodeToString([]byte{b})
		}
		return out
	}
	cases := []struct {
		name string
		der  []byte
		want []byte
	}{
		{"small ints are left padded", h("3006020101020102"), append(append(make([]byte, 31), 1), append(make([]byte, 31), 2)...)},
		{"leading 0x00 sign byte stripped", h("30" + "46" + "0221" + "00" + pad(32, 0x80) + "0221" + "00" + pad(32, 0xff)), h(pad(32, 0x80) + pad(32, 0xff))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := DERToJOSE(c.der, 32)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != hex.EncodeToString(c.want) {
				t.Fatalf("got %x want %x", got, c.want)
			}
		})
	}
}

func TestDERToJOSE_RoundTripVerifies(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for i := 0; i < 200; i++ {
		d := sha256.Sum256([]byte{byte(i)})
		der, err := ecdsa.SignASN1(rand.Reader, key, d[:])
		if err != nil {
			t.Fatal(err)
		}
		raw, err := DERToJOSE(der, 32)
		if err != nil || len(raw) != 64 {
			t.Fatalf("convert: %v len=%d", err, len(raw))
		}
		if !ecdsa.Verify(&key.PublicKey, d[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])) {
			t.Fatalf("iteration %d: converted signature does not verify", i)
		}
	}
}

func TestDERToJOSE_Rejects(t *testing.T) {
	big33 := new(big.Int).Lsh(big.NewInt(1), 256)
	mk := func(r, s *big.Int) []byte {
		b, _ := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		return b
	}
	good := mk(big.NewInt(5), big.NewInt(6))
	cases := map[string][]byte{
		"garbage":     {1, 2, 3},
		"empty":       nil,
		"trailing":    append(append([]byte{}, good...), 0),
		"zero r":      mk(big.NewInt(0), big.NewInt(6)),
		"negative s":  mk(big.NewInt(5), big.NewInt(-6)),
		"r too large": mk(big33, big.NewInt(6)),
		"s too large": mk(big.NewInt(5), big33),
		"single int":  {0x30, 0x03, 0x02, 0x01, 0x01},
	}
	for n, der := range cases {
		if _, err := DERToJOSE(der, 32); err == nil {
			t.Errorf("%s: expected error", n)
		}
	}
}

type fakeKMS struct {
	ec     *ecdsa.PrivateKey
	rsa    *rsa.PrivateKey
	err    error
	gotAlg string
	gotKey string
	pubs   int
}

func (f *fakeKMS) SignDigest(_ context.Context, keyID string, d []byte, alg string) ([]byte, error) {
	f.gotAlg, f.gotKey = alg, keyID
	if f.err != nil {
		return nil, f.err
	}
	if alg == AlgSpecECDSA {
		return ecdsa.SignASN1(rand.Reader, f.ec, d)
	}
	return rsa.SignPKCS1v15(rand.Reader, f.rsa, crypto.SHA256, d)
}

func (f *fakeKMS) PublicKeyDER(context.Context, string) ([]byte, error) {
	f.pubs++
	if f.err != nil {
		return nil, f.err
	}
	if f.ec != nil {
		return x509.MarshalPKIXPublicKey(&f.ec.PublicKey)
	}
	return x509.MarshalPKIXPublicKey(&f.rsa.PublicKey)
}

func newFake(t *testing.T) *fakeKMS {
	t.Helper()
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeKMS{ec: ec, rsa: rk}
}

func TestNew_Validation(t *testing.T) {
	if _, err := New(nil, "k", "kid"); !errors.Is(err, domain.ErrConfig) {
		t.Fatal("nil api must be ErrConfig")
	}
	if _, err := New(&fakeKMS{}, "", "kid"); !errors.Is(err, domain.ErrConfig) {
		t.Fatal("empty key id must be ErrConfig")
	}
}

func TestSign_ES256_A01_A10(t *testing.T) {
	f := newFake(t)
	s, _ := New(f, "arn:key", "kid-1")
	in := []byte("header.payload")
	sig, kid, err := s.Sign(context.Background(), "ES256", in)
	if err != nil || kid != "kid-1" || len(sig) != 64 {
		t.Fatalf("sig=%d kid=%q err=%v", len(sig), kid, err)
	}
	d := sha256.Sum256(in)
	if !ecdsa.Verify(&f.ec.PublicKey, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("ES256 signature does not verify")
	}
	if f.gotAlg != AlgSpecECDSA || f.gotKey != "arn:key" {
		t.Fatalf("api args %q %q", f.gotAlg, f.gotKey)
	}
}

func TestSign_RS256(t *testing.T) {
	f := newFake(t)
	s, _ := New(f, "k", "kid")
	in := []byte("a.b")
	sig, _, err := s.Sign(context.Background(), "RS256", in)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(in)
	if err := rsa.VerifyPKCS1v15(&f.rsa.PublicKey, crypto.SHA256, d[:], sig); err != nil {
		t.Fatal(err)
	}
}

func TestSign_Errors(t *testing.T) {
	f := newFake(t)
	s, _ := New(f, "k", "kid")
	if _, _, err := s.Sign(context.Background(), "HS256", nil); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("bad alg: %v", err)
	}
	f.err = errors.New("throttled")
	if _, _, err := s.Sign(context.Background(), "ES256", nil); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("api failure must be transient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.Sign(ctx, "ES256", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

type badDERKMS struct{ fakeKMS }

func (b *badDERKMS) SignDigest(context.Context, string, []byte, string) ([]byte, error) {
	return []byte{1, 2, 3}, nil
}

func TestSign_MalformedDER_A10(t *testing.T) {
	s, _ := New(&badDERKMS{}, "k", "kid")
	if _, _, err := s.Sign(context.Background(), "ES256", nil); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("want ErrProvider, got %v", err)
	}
}

func TestPublic(t *testing.T) {
	f := newFake(t)
	f.rsa = nil
	s, _ := New(f, "k", "kid-9")
	for i := 0; i < 2; i++ {
		j, err := s.Public()
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]string
		_ = json.Unmarshal(j, &m)
		if m["kty"] != "EC" || m["crv"] != "P-256" || m["kid"] != "kid-9" || m["alg"] != "ES256" || m["x"] == "" || m["y"] == "" {
			t.Fatalf("jwk %v", m)
		}
	}
	if f.pubs != 1 {
		t.Fatalf("public key should be cached, fetched %d", f.pubs)
	}
	g := newFake(t)
	g.ec = nil
	rs, _ := New(g, "k", "kid")
	j, err := rs.Public()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	_ = json.Unmarshal(j, &m)
	if m["kty"] != "RSA" || m["alg"] != "RS256" || m["n"] == "" || m["e"] != "AQAB" {
		t.Fatalf("jwk %v", m)
	}
}

func TestPublic_Errors(t *testing.T) {
	f := &fakeKMS{err: errors.New("boom")}
	s, _ := New(f, "k", "")
	if _, err := s.Public(); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("%v", err)
	}
	s2, _ := New(&junkPub{}, "k", "")
	if _, err := s2.Public(); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("%v", err)
	}
}

type junkPub struct{ fakeKMS }

func (junkPub) PublicKeyDER(context.Context, string) ([]byte, error) { return []byte("x"), nil }

func TestPublicJWK_Errors(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := PublicJWK(&rk.PublicKey, "ES256", ""); err == nil {
		t.Error("rsa with ES256")
	}
	if _, err := PublicJWK(&ec.PublicKey, "RS256", ""); err == nil {
		t.Error("ec with RS256")
	}
	if _, err := PublicJWK(&p384.PublicKey, "ES256", ""); err == nil {
		t.Error("p384")
	}
	if _, err := PublicJWK("nope", "ES256", ""); err == nil {
		t.Error("type")
	}
	if AlgFor("x") != "" {
		t.Error("AlgFor unknown")
	}
}
