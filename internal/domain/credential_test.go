package domain

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func goodCred() Credential {
	return Credential{Kind: KindBearer, Value: NewSecret(sample), IssuedAt: t0, ExpiresAt: t0.Add(time.Hour), Meta: map[string]string{MetaAudience: "api://x"}}
}

func TestCredentialValidate(t *testing.T) {
	if err := goodCred().Validate(); err != nil {
		t.Fatal(err)
	}
	mut := map[string]func(*Credential){
		"empty value":    func(c *Credential) { c.Value = SecretString{} },
		"bad kind":       func(c *Credential) { c.Kind = "nope" },
		"empty kind":     func(c *Credential) { c.Kind = "" },
		"zero expires":   func(c *Credential) { c.ExpiresAt = time.Time{} },
		"zero ttl":       func(c *Credential) { c.ExpiresAt = c.IssuedAt },
		"negative ttl":   func(c *Credential) { c.ExpiresAt = c.IssuedAt.Add(-time.Second) },
		"zero issued at": func(c *Credential) { c.IssuedAt = time.Time{} },
	}
	for name, m := range mut {
		c := goodCred()
		m(&c)
		err := c.Validate()
		if !errors.Is(err, ErrProvider) {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), sample) {
			t.Errorf("%s leaked secret", name)
		}
	}
	for _, k := range []Kind{KindBearer, KindAWSWebIdentity, KindStaticSecret} {
		if !k.Valid() {
			t.Fatal(k)
		}
	}
}

func TestCredentialTiming(t *testing.T) {
	c := goodCred()
	if c.TTL() != time.Hour || c.Remaining(t0.Add(15*time.Minute)) != 45*time.Minute {
		t.Fatal("TTL/Remaining")
	}
	if got := c.Elapsed(t0.Add(30 * time.Minute)); got != 0.5 {
		t.Fatalf("Elapsed %v", got)
	}
	if c.Elapsed(t0.Add(-time.Minute)) != 0 || c.Elapsed(t0.Add(2*time.Hour)) != 1 {
		t.Fatal("clamp")
	}
	if c.Expired(t0.Add(59*time.Minute)) || !c.Expired(t0.Add(time.Hour)) {
		t.Fatal("Expired")
	}
	if c.Remaining(t0.Add(2*time.Hour)) != 0 {
		t.Fatal("Remaining clamps at 0")
	}
	z := Credential{}
	if z.Elapsed(t0) != 1 {
		t.Fatal("zero ttl counts as fully elapsed")
	}
	if c.Audience() != "api://x" || (Credential{}).Audience() != "" {
		t.Fatal("Audience")
	}
}

func TestCredentialNeverPrintsSecret(t *testing.T) {
	c := goodCred()
	out := fmt.Sprintf("%v %+v %#v", c, c, c)
	if strings.Contains(out, sample) {
		t.Fatal(out)
	}
}

func TestKey(t *testing.T) {
	k := Key{Provider: "aws", Audience: "a", Scope: "s"}
	if k.String() != "aws|a|s" {
		t.Fatal(k.String())
	}
	if k == (Key{Provider: "aws", Audience: "a"}) {
		t.Fatal("comparable")
	}
}

func TestCacheEntryStatus(t *testing.T) {
	e := CacheEntry{Key: Key{Provider: "aws"}, State: StateDegraded, LastError: Wrap(ErrAuthDefinitive, errors.New("x"))}
	if e.LastErrorClass() != "auth_definitive" || (CacheEntry{}).LastErrorClass() != "" {
		t.Fatal("LastErrorClass")
	}
}
