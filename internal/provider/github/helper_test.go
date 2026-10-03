package github

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/domain/domaintest"
)

func credSrc(token string, err error) CredentialSource {
	return func(context.Context) (domain.Credential, error) {
		if err != nil {
			return domain.Credential{}, err
		}
		return domain.Credential{Kind: domain.KindStaticSecret, Value: domain.NewSecret(token), IssuedAt: domaintest.Epoch, ExpiresAt: domaintest.Epoch.Add(time.Hour)}, nil
	}
}

func TestHelperGet(t *testing.T) {
	var out bytes.Buffer
	in := "protocol=https\nhost=github.com\npath=acme/widgets.git\n\n"
	err := RunCredentialHelper(context.Background(), "get", strings.NewReader(in), &out, credSrc("ghp_tok", nil), HelperOptions{Login: "agent-x_acme", WebBase: "https://github.com"})
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "username=agent-x_acme\npassword=ghp_tok\n" {
		t.Fatalf("out=%q", out.String())
	}
}

func TestHelperGetOtherHostOrProtocolIsSilent(t *testing.T) {
	for _, in := range []string{"protocol=https\nhost=gitlab.com\n\n", "protocol=http\nhost=github.com\n\n", "host=github.com\n\n", ""} {
		var out bytes.Buffer
		called := false
		src := func(ctx context.Context) (domain.Credential, error) { called = true; return credSrc("x", nil)(ctx) }
		if err := RunCredentialHelper(context.Background(), "get", strings.NewReader(in), &out, src, HelperOptions{Login: "l", WebBase: "https://github.com"}); err != nil {
			t.Fatal(err)
		}
		if out.Len() != 0 || called {
			t.Fatalf("input %q: out=%q called=%v", in, out.String(), called)
		}
	}
}

func TestHelperGetGHES(t *testing.T) {
	var out bytes.Buffer
	in := "protocol=https\nhost=ghe.example.com:8443\n\n"
	_ = RunCredentialHelper(context.Background(), "get", strings.NewReader(in), &out, credSrc("t", nil), HelperOptions{Login: "l", WebBase: "https://ghe.example.com:8443"})
	if !strings.Contains(out.String(), "password=t") {
		t.Fatalf("out=%q", out.String())
	}
}

func TestHelperStoreEraseNoop(t *testing.T) {
	for _, op := range []string{"store", "erase"} {
		var out bytes.Buffer
		called := false
		src := func(context.Context) (domain.Credential, error) { called = true; return domain.Credential{}, nil }
		in := "protocol=https\nhost=github.com\nusername=u\npassword=NEWSECRET\n\n"
		if err := RunCredentialHelper(context.Background(), op, strings.NewReader(in), &out, src, HelperOptions{Login: "l", WebBase: "https://github.com"}); err != nil {
			t.Fatal(err)
		}
		if out.Len() != 0 || called {
			t.Fatalf("%s must be a no-op", op)
		}
	}
}

func TestHelperErrors(t *testing.T) {
	opt := HelperOptions{Login: "l", WebBase: "https://github.com"}
	in := "protocol=https\nhost=github.com\n\n"
	var out bytes.Buffer
	if err := RunCredentialHelper(context.Background(), "bogus", strings.NewReader(in), &out, credSrc("t", nil), opt); err == nil {
		t.Fatal("unknown op must error")
	}
	boom := errors.New("daemon down")
	err := RunCredentialHelper(context.Background(), "get", strings.NewReader(in), &out, credSrc("", boom), opt)
	if !errors.Is(err, boom) || out.Len() != 0 {
		t.Fatalf("err=%v out=%q", err, out.String())
	}
	// an empty token must never be emitted
	if err := RunCredentialHelper(context.Background(), "get", strings.NewReader(in), &out, credSrc("", nil), opt); err == nil || out.Len() != 0 {
		t.Fatalf("empty token: err=%v out=%q", err, out.String())
	}
	// option validation
	if err := RunCredentialHelper(context.Background(), "get", strings.NewReader(in), &out, credSrc("t", nil), HelperOptions{}); !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("got %v", err)
	}
}

func TestHelperGetRejectsInjectedNewlines(t *testing.T) {
	var out bytes.Buffer
	err := RunCredentialHelper(context.Background(), "get", strings.NewReader("protocol=https\nhost=github.com\n\n"), &out, credSrc("a\nb", nil), HelperOptions{Login: "l", WebBase: "https://github.com"})
	if err == nil || out.Len() != 0 {
		t.Fatalf("err=%v out=%q", err, out.String())
	}
}
