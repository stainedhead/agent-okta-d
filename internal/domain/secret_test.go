package domain

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const sample = "tok-SUPER-secret-123"

func TestSecretStringRedactsEverywhere(t *testing.T) {
	s := NewSecret(sample)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d", "%T"} {
		out := fmt.Sprintf(verb, s)
		if strings.Contains(out, sample) {
			t.Fatalf("verb %s leaked: %q", verb, out)
		}
	}
	if got := fmt.Sprint(s); got != Redacted {
		t.Fatalf("Sprint = %q", got)
	}
	if fmt.Sprintf("%#v", s) != "domain.SecretString{[redacted]}" {
		t.Fatalf("GoString = %q", fmt.Sprintf("%#v", s))
	}
	if s.String() != Redacted || s.GoString() == "" {
		t.Fatal("String/GoString")
	}
}

func TestSecretStringJSONTextSlog(t *testing.T) {
	s := NewSecret(sample)
	b, err := json.Marshal(struct {
		V SecretString `json:"v"`
		P *SecretString
	}{V: s, P: &s})
	if err != nil || strings.Contains(string(b), sample) {
		t.Fatalf("json: %s %v", b, err)
	}
	if !strings.Contains(string(b), Redacted) {
		t.Fatalf("json lacks marker: %s", b)
	}
	txt, err := s.MarshalText()
	if err != nil || string(txt) != Redacted {
		t.Fatalf("text: %q %v", txt, err)
	}
	var sb strings.Builder
	l := slog.New(slog.NewJSONHandler(&sb, nil))
	l.Info("x", "secret", s, slog.Any("g", s))
	if strings.Contains(sb.String(), sample) {
		t.Fatalf("slog leaked: %s", sb.String())
	}
	if s.LogValue().String() != Redacted {
		t.Fatal("LogValue")
	}
	// within a nested struct and a map
	out := fmt.Sprintf("%v %+v", map[string]SecretString{"a": s}, struct{ S SecretString }{s})
	if strings.Contains(out, sample) {
		t.Fatalf("nested leaked: %s", out)
	}
}

func TestSecretStringAccessors(t *testing.T) {
	s := NewSecret(sample)
	if s.Reveal() != sample || s.Len() != len(sample) || s.IsZero() {
		t.Fatal("accessors")
	}
	var z SecretString
	if !z.IsZero() || z.Reveal() != "" || z.String() != Redacted {
		t.Fatal("zero value")
	}
	if !s.Equal(NewSecret(sample)) || s.Equal(NewSecret("other")) || s.Equal(z) {
		t.Fatal("Equal")
	}
}

func FuzzSecretStringNeverLeaks(f *testing.F) {
	f.Add("abcdefgh-secret")
	f.Add("")
	f.Add("[redacted]x")
	f.Fuzz(func(t *testing.T, v string) {
		if len(v) < 6 || strings.Contains(Redacted, v) || strings.Contains("domain.SecretString{}", v) {
			t.Skip()
		}
		s := NewSecret(v)
		b, _ := json.Marshal(s)
		all := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x|%d", s, s, s, s, s, s, s) + string(b)
		if strings.Contains(all, v) {
			t.Fatalf("leak of %q in %q", v, all)
		}
	})
}
