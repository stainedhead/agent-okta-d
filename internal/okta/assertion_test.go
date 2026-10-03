package okta_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/domain/domaintest"
	"github.com/stainedhead/agent-okta-d/internal/okta"
)

func decode(t *testing.T, seg string, v any) {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func newBuilder() (*okta.AssertionBuilder, *domaintest.FakeSigner, *domaintest.FakeClock) {
	sg := &domaintest.FakeSigner{KID: "kid-77"}
	ck := domaintest.NewFakeClock()
	return &okta.AssertionBuilder{ClientID: "0oa123", Signer: sg, Clock: ck}, sg, ck
}

func TestAssertionClaimsAndHeader(t *testing.T) {
	b, _, ck := newBuilder()
	const aud = "https://example.okta.com/oauth2/aus1/v1/token"
	a, err := b.Build(context.Background(), aud)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(a.JWT.Reveal(), ".")
	if len(parts) != 3 {
		t.Fatalf("parts %d", len(parts))
	}
	var h map[string]string
	decode(t, parts[0], &h)
	if h["alg"] != "RS256" || h["kid"] != "kid-77" || h["typ"] != "JWT" {
		t.Fatalf("header %v", h)
	}
	var c struct {
		Iss, Sub, Aud, Jti string
		Iat, Exp           int64
	}
	decode(t, parts[1], &c)
	now := ck.Now().Unix()
	if c.Iss != "0oa123" || c.Sub != "0oa123" || c.Aud != aud {
		t.Fatalf("claims %+v", c)
	}
	if c.Iat != now || c.Exp != now+60 {
		t.Fatalf("iat/exp %d %d now %d", c.Iat, c.Exp, now)
	}
	if c.Jti == "" || c.Jti != a.JTI || a.KID != "kid-77" {
		t.Fatalf("jti %q %q", c.Jti, a.JTI)
	}
	if !a.ExpiresAt.Equal(a.IssuedAt.Add(60 * time.Second)) {
		t.Fatal("expires")
	}
	if want := "sig:RS256:" + parts[0] + "." + parts[1]; string(mustB64(t, parts[2])) != want {
		t.Fatal("signature input mismatch")
	}
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAssertionJTIUnique(t *testing.T) {
	b, _, _ := newBuilder()
	seen := map[string]bool{}
	for range 200 {
		a, err := b.Build(context.Background(), "aud")
		if err != nil {
			t.Fatal(err)
		}
		if seen[a.JTI] {
			t.Fatal("duplicate jti")
		}
		seen[a.JTI] = true
	}
}

func TestAssertionSecretIsRedacted(t *testing.T) {
	b, _, _ := newBuilder()
	a, _ := b.Build(context.Background(), "aud")
	if s := fmtAll(a); strings.Contains(s, a.JWT.Reveal()) {
		t.Fatal("assertion leaked through formatting")
	}
}

func fmtAll(v any) string {
	return strings.Join([]string{sprint("%v", v), sprint("%+v", v), sprint("%#v", v)}, "|")
}

func TestAssertionKIDProbedOnce(t *testing.T) {
	b, sg, _ := newBuilder()
	for range 3 {
		if _, err := b.Build(context.Background(), "aud"); err != nil {
			t.Fatal(err)
		}
	}
	// 1 probe + 3 real signatures
	if len(sg.Calls) != 4 {
		t.Fatalf("sign calls %d", len(sg.Calls))
	}
}

type kidSigner struct {
	*domaintest.FakeSigner
	calls int
}

func (k *kidSigner) KID() string { return "from-method" }
func (k *kidSigner) Sign(ctx context.Context, alg string, in []byte) ([]byte, string, error) {
	k.calls++
	return k.FakeSigner.Sign(ctx, alg, in)
}

func TestAssertionUsesSignerKIDMethodWithoutProbe(t *testing.T) {
	ks := &kidSigner{FakeSigner: &domaintest.FakeSigner{KID: "from-method"}}
	b := &okta.AssertionBuilder{ClientID: "c", Signer: ks, Clock: domaintest.NewFakeClock()}
	a, err := b.Build(context.Background(), "aud")
	if err != nil || ks.calls != 1 || a.KID != "from-method" {
		t.Fatalf("err=%v calls=%d kid=%s", err, ks.calls, a.KID)
	}
}

// ASSUMPTION(A-01): ES256 is accepted by Okta; the builder passes the alg to the signer.
func TestAssertionES256A01(t *testing.T) {
	b, _, _ := newBuilder()
	b.Alg = okta.AlgES256
	a, err := b.Build(context.Background(), "aud")
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]string
	decode(t, strings.Split(a.JWT.Reveal(), ".")[0], &h)
	if h["alg"] != "ES256" {
		t.Fatalf("alg %s", h["alg"])
	}
}

func TestAssertionCustomTTLAndRand(t *testing.T) {
	b, _, ck := newBuilder()
	b.TTL = 30 * time.Second
	b.Rand = strings.NewReader(strings.Repeat("\x01", 16))
	a, err := b.Build(context.Background(), "aud")
	if err != nil {
		t.Fatal(err)
	}
	if a.JTI != strings.Repeat("01", 16) || !a.ExpiresAt.Equal(ck.Now().Add(30*time.Second)) {
		t.Fatalf("%+v", a)
	}
	b.Rand = strings.NewReader("short")
	if _, err := b.Build(context.Background(), "aud"); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("want ErrProvider, got %v", err)
	}
}

func TestAssertionConfigErrors(t *testing.T) {
	sg := &domaintest.FakeSigner{}
	ck := domaintest.NewFakeClock()
	cases := map[string]*okta.AssertionBuilder{
		"no client": {Signer: sg, Clock: ck},
		"no signer": {ClientID: "c", Clock: ck},
		"no clock":  {ClientID: "c", Signer: sg},
		"bad alg":   {ClientID: "c", Signer: sg, Clock: ck, Alg: "none"},
		"neg ttl":   {ClientID: "c", Signer: sg, Clock: ck, TTL: -1},
		"huge ttl":  {ClientID: "c", Signer: sg, Clock: ck, TTL: 2 * time.Hour},
	}
	for name, b := range cases {
		if _, err := b.Build(context.Background(), "aud"); !errors.Is(err, domain.ErrConfig) {
			t.Errorf("%s: want ErrConfig, got %v", name, err)
		}
	}
	good := &okta.AssertionBuilder{ClientID: "c", Signer: sg, Clock: ck}
	if _, err := good.Build(context.Background(), ""); !errors.Is(err, domain.ErrConfig) {
		t.Errorf("empty aud: %v", err)
	}
}

func TestAssertionSignerFailureClassification(t *testing.T) {
	ck := domaintest.NewFakeClock()
	// unclassified error text must not leak
	b := &okta.AssertionBuilder{ClientID: "c", Clock: ck, Signer: &domaintest.FakeSigner{Err: errors.New("kms said SECRET-TEXT")}}
	_, err := b.Build(context.Background(), "aud")
	if !errors.Is(err, domain.ErrProvider) || strings.Contains(err.Error(), "SECRET-TEXT") {
		t.Fatalf("got %v", err)
	}
	// classified errors survive
	b = &okta.AssertionBuilder{ClientID: "c", Clock: ck, Signer: &domaintest.FakeSigner{Err: domain.NewTransient(errors.New("net"), 0)}}
	if _, err := b.Build(context.Background(), "aud"); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("got %v", err)
	}
	b = &okta.AssertionBuilder{ClientID: "c", Clock: ck, Signer: &domaintest.FakeSigner{Err: context.Canceled}}
	if _, err := b.Build(context.Background(), "aud"); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

type emptyKID struct{}

func (emptyKID) Sign(context.Context, string, []byte) ([]byte, string, error) {
	return []byte("s"), "", nil
}
func (emptyKID) Public() ([]byte, error) { return nil, nil }

type driftKID struct{ n int }

func (d *driftKID) Sign(context.Context, string, []byte) ([]byte, string, error) {
	d.n++
	return []byte("s"), "kid" + string(rune('0'+d.n)), nil
}
func (*driftKID) Public() ([]byte, error) { return nil, nil }

func TestAssertionKIDEdgeCases(t *testing.T) {
	ck := domaintest.NewFakeClock()
	b := &okta.AssertionBuilder{ClientID: "c", Clock: ck, Signer: emptyKID{}}
	if _, err := b.Build(context.Background(), "aud"); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("empty kid: %v", err)
	}
	// kid changing between probe and signature (key rotation mid-flight) is refused
	b = &okta.AssertionBuilder{ClientID: "c", Clock: ck, Signer: &driftKID{}}
	if _, err := b.Build(context.Background(), "aud"); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("drift: %v", err)
	}
}

func TestAssertionRealRSASignatureVerifies(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b := &okta.AssertionBuilder{ClientID: "c", Clock: domaintest.NewFakeClock(), Signer: rsaSigner{k}}
	a, err := b.Build(context.Background(), "aud")
	if err != nil {
		t.Fatal(err)
	}
	p := strings.Split(a.JWT.Reveal(), ".")
	h := sha256.Sum256([]byte(p[0] + "." + p[1]))
	if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, h[:], mustB64(t, p[2])); err != nil {
		t.Fatal(err)
	}
}

type rsaSigner struct{ k *rsa.PrivateKey }

func (r rsaSigner) Sign(_ context.Context, _ string, in []byte) ([]byte, string, error) {
	h := sha256.Sum256(in)
	s, err := rsa.SignPKCS1v15(rand.Reader, r.k, crypto.SHA256, h[:])
	return s, "k1", err
}
func (rsaSigner) Public() ([]byte, error) { return nil, nil }
