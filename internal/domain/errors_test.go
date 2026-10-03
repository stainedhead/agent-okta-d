package domain

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestSentinelsDistinct(t *testing.T) {
	all := []error{ErrTransient, ErrAuthDefinitive, ErrConfig, ErrPolicy, ErrProvider, ErrReauthRequired, ErrRevoked, ErrNotFound, ErrVersionConflict}
	for i, a := range all {
		for j, b := range all {
			if (i == j) != errors.Is(a, b) {
				t.Fatalf("%v vs %v", a, b)
			}
		}
	}
}

func TestProviderError(t *testing.T) {
	cause := errors.New("boom")
	e := NewProviderError("aws", cause)
	if !errors.Is(e, ErrProvider) || !errors.Is(e, cause) || errors.Is(e, ErrTransient) {
		t.Fatal("Is")
	}
	if e.Error() != "provider aws: boom" {
		t.Fatal(e.Error())
	}
	var pe *ProviderError
	if !errors.As(fmt.Errorf("w: %w", e), &pe) || pe.Provider != "aws" {
		t.Fatal("As")
	}
	if NewProviderError("x", nil).Error() != "provider x: failed" {
		t.Fatal("nil cause")
	}
}

func TestTransientError(t *testing.T) {
	cause := errors.New("503")
	e := NewTransient(cause, 7*time.Second)
	if !errors.Is(e, ErrTransient) || !errors.Is(e, cause) {
		t.Fatal("Is")
	}
	d, ok := RetryAfter(fmt.Errorf("w: %w", e))
	if !ok || d != 7*time.Second {
		t.Fatal("RetryAfter")
	}
	if _, ok := RetryAfter(errors.New("x")); ok {
		t.Fatal("no retry-after expected")
	}
	if _, ok := RetryAfter(NewTransient(cause, 0)); ok {
		t.Fatal("zero is not a hint")
	}
	if NewTransient(nil, 0).Error() != "transient error" {
		t.Fatal("nil cause text")
	}
}

func TestConfigError(t *testing.T) {
	e := NewConfigError("providers.aws.role_arn", "must not be empty")
	if !errors.Is(e, ErrConfig) {
		t.Fatal("Is")
	}
	if e.Error() != "config: providers.aws.role_arn: must not be empty" {
		t.Fatal(e.Error())
	}
	var ce *ConfigError
	if !errors.As(e, &ce) || ce.Field != "providers.aws.role_arn" {
		t.Fatal("As")
	}
}

func TestWrapSentinel(t *testing.T) {
	e := Wrap(ErrAuthDefinitive, errors.New("invalid_client"))
	if !errors.Is(e, ErrAuthDefinitive) || e.Error() != "auth definitive: invalid_client" {
		t.Fatalf("%v", e)
	}
	if Wrap(ErrPolicy, nil).Error() != "policy violation" {
		t.Fatal("nil cause")
	}
}

func TestErrorClass(t *testing.T) {
	cases := map[string]error{
		"":                nil,
		"transient":       NewTransient(errors.New("x"), 0),
		"auth_definitive": Wrap(ErrAuthDefinitive, errors.New("x")),
		"config":          NewConfigError("f", "m"),
		"policy":          ErrPolicy,
		"provider":        NewProviderError("p", nil),
		"reauth_required": fmt.Errorf("w: %w", ErrReauthRequired),
		"revoked":         ErrRevoked,
		"not_found":       ErrNotFound,
		"conflict":        ErrVersionConflict,
		"unknown":         errors.New("other"),
	}
	for want, err := range cases {
		if got := ErrorClass(err); got != want {
			t.Errorf("ErrorClass(%v) = %q want %q", err, got, want)
		}
	}
}

func TestExitCode(t *testing.T) {
	if ExitCode(nil) != ExitOK || ExitCode(ErrRevoked) != ExitRevoked || ExitCode(NewConfigError("a", "b")) != ExitConfig || ExitCode(errors.New("x")) != ExitFailure {
		t.Fatal("exit codes")
	}
	if ExitRevoked != 77 || ExitConfig != 78 || ExitOK != 0 {
		t.Fatal("frozen values")
	}
}
