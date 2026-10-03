package github

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/domain/domaintest"
)

func TestStoredRoundTrip(t *testing.T) {
	exp := domaintest.Epoch.Add(48 * time.Hour)
	in := Stored{Mode: ModePAT, Token: "ghp_secret", ExpiresAt: exp, Scope: "repo"}
	sec, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sec.String(), "ghp_") {
		t.Fatal("secret string leaked")
	}
	out, err := ParseStored(sec)
	if err != nil {
		t.Fatal(err)
	}
	if out.Token != "ghp_secret" || out.Mode != ModePAT || !out.ExpiresAt.Equal(exp) || out.Scope != "repo" {
		t.Fatalf("round trip: %+v", out)
	}
}

func TestParseStoredRawToken(t *testing.T) {
	out, err := ParseStored(domain.NewSecret("  ghp_raw\n"))
	if err != nil || out.Token != "ghp_raw" || !out.ExpiresAt.IsZero() || out.Mode != "" {
		t.Fatalf("raw: %+v %v", out, err)
	}
}

func TestParseStoredErrors(t *testing.T) {
	for name, v := range map[string]string{"empty": "", "blank": "  \n", "badjson": "{nope", "notoken": `{"v":1,"mode":"pat"}`, "badmode": `{"v":1,"mode":"zzz","token":"x"}`, "badver": `{"v":9,"token":"x"}`} {
		if _, err := ParseStored(domain.NewSecret(v)); err == nil {
			t.Errorf("%s: want error", name)
		} else if !errors.Is(err, domain.ErrProvider) {
			t.Errorf("%s: want ErrProvider, got %v", name, err)
		}
	}
}

func TestStoredEncodeRejectsEmpty(t *testing.T) {
	if _, err := (Stored{}).Encode(); err == nil {
		t.Fatal("want error")
	}
}

func TestExpiryStatus(t *testing.T) {
	now := domaintest.Epoch
	day := 24 * time.Hour
	cases := []struct {
		name string
		exp  time.Time
		want ExpiryState
	}{
		{"none", time.Time{}, ExpiryUnknown},
		{"far", now.Add(90 * day), ExpiryOK},
		{"boundary", now.Add(30 * day), ExpiryWarn},
		{"soon", now.Add(3 * day), ExpiryWarn},
		{"at", now, ExpiryExpired},
		{"past", now.Add(-time.Hour), ExpiryExpired},
	}
	for _, c := range cases {
		if got := ExpiryStatus(c.exp, now, 30); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
