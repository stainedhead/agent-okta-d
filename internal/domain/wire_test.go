package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func golden(t *testing.T, name string, v any) {
	t.Helper()
	want, err := os.ReadFile(filepath.Join("testdata", "wire", name))
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	if err := json.Compact(&w, want); err != nil {
		t.Fatal(err)
	}
	if string(got) != w.String() {
		t.Fatalf("%s drifted:\n got %s\nwant %s", name, got, w.String())
	}
}

func TestWireGolden(t *testing.T) {
	exp := t0.Add(time.Hour)
	golden(t, "credential.json", NewWireCredential(goodCred()))
	golden(t, "status.json", WireStatus{State: StateDegraded, Providers: []WireProviderStatus{
		{Provider: "aws", State: StateValid, ExpiresAt: &exp},
		{Provider: "github", State: StateReauthRequired, LastError: "reauth_required"},
		{Provider: "snow", State: StateDegraded, LastError: "transient", RetryAfter: 12},
	}})
	golden(t, "identity.json", WireIdentity{AgentID: "agent-007", OktaClientID: "0oaEXAMPLE", KID: "kid-1", DaemonVersion: "0.1.0", APIVersion: APIVersion})
	golden(t, "health.json", WireHealth{Status: "ok"})
	golden(t, "error_degraded.json", WireError{Error: CodeDegraded, State: StateDegraded, RetryAfterSeconds: 30})
}

func TestWireCredentialRoundTripAndRedaction(t *testing.T) {
	raw, err := os.ReadFile("testdata/wire/credential.json")
	if err != nil {
		t.Fatal(err)
	}
	var w WireCredential
	if err := json.Unmarshal(raw, &w); err != nil || w.AccessToken != sample || w.TokenType != "Bearer" {
		t.Fatalf("%+v %v", w, err)
	}
	for _, out := range []string{fmt.Sprintf("%v", w), fmt.Sprintf("%+v", w), fmt.Sprintf("%#v", w), w.String()} {
		if strings.Contains(out, sample) {
			t.Fatalf("leak: %s", out)
		}
	}
	c := goodCred()
	c.Kind = KindAWSWebIdentity
	if NewWireCredential(c).TokenType != "aws-web-identity" {
		t.Fatal("non-bearer token type")
	}
}

func TestHTTPStatusAndCodes(t *testing.T) {
	want := map[string]int{
		CodeReauthRequired: 401, CodeRevoked: 403, CodeUnauthorized: 403, CodeNotConfigured: 404,
		CodeDegraded: 503, CodeInternal: 500, "weird": http.StatusInternalServerError,
	}
	for c, s := range want {
		if HTTPStatus(c) != s {
			t.Errorf("%s", c)
		}
	}
	for st, code := range map[State]string{StateReauthRequired: CodeReauthRequired, StateRevoked: CodeRevoked, StateDegraded: CodeDegraded, StateEmpty: CodeDegraded, StateMinting: CodeDegraded} {
		if got, ok := CodeForState(st); !ok || got != code {
			t.Errorf("%s", st)
		}
	}
	for _, st := range []State{StateValid, StateRefreshing} {
		if _, ok := CodeForState(st); ok {
			t.Errorf("%s has no code", st)
		}
	}
}
