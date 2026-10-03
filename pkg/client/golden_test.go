package client_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stainedhead/agent-okta-d/pkg/client"
	"github.com/stainedhead/agent-okta-d/pkg/client/clienttest"
)

// Golden wire tests (CLI-5). testdata/*.json mirror
// internal/domain/testdata/wire; JSON field names must not drift.

func golden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(b)
}

func jsonEqual(t *testing.T, got any, want []byte) {
	t.Helper()
	gb, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var g, w any
	if err := json.Unmarshal(gb, &g); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("wire drift:\n got %s\nwant %s", gb, want)
	}
}

func TestGoldenClientTypes(t *testing.T) {
	var st client.Status
	var id client.Identity
	for name, v := range map[string]any{"status.json": &st, "identity.json": &id} {
		if err := json.Unmarshal(golden(t, name), v); err != nil {
			t.Fatal(err)
		}
		jsonEqual(t, v, golden(t, name))
	}
	if st.Providers[2].RetryAfterSeconds != 12 || id.APIVersion != "v1" {
		t.Fatalf("%+v %+v", st, id)
	}
}

func TestGoldenCredential(t *testing.T) {
	var c client.Credential
	if err := json.Unmarshal(golden(t, "credential.json"), &c); err != nil {
		t.Fatal(err)
	}
	if c.AccessToken.Reveal() != "tok-SUPER-secret-123" || c.TokenType != "Bearer" || c.Audience != "api://x" {
		t.Fatalf("%v", c)
	}
	// Re-encoding must keep the field names and redact the token.
	b, _ := json.Marshal(c)
	var got, want map[string]any
	_ = json.Unmarshal(b, &got)
	_ = json.Unmarshal(golden(t, "credential.json"), &want)
	if got["access_token"] != client.Redacted {
		t.Fatalf("token not redacted: %s", b)
	}
	want["access_token"] = client.Redacted
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("wire drift:\n got %s\nwant %v", b, want)
	}
}

func TestGoldenFakeDaemonTypes(t *testing.T) {
	var c clienttest.Credential
	var st clienttest.Status
	var id clienttest.Identity
	for name, v := range map[string]any{"credential.json": &c, "status.json": &st, "identity.json": &id} {
		if err := json.Unmarshal(golden(t, name), v); err != nil {
			t.Fatal(err)
		}
		jsonEqual(t, v, golden(t, name))
	}
}

func TestGoldenErrorBody(t *testing.T) {
	c, srv := newPair(t)
	srv.SetProviderError("p", clienttest.Error{Code: clienttest.CodeDegraded, State: "degraded", RetryAfter: 30e9})
	_, err := c.Credential(t.Context(), "p")
	if d, ok := client.RetryAfter(err); !ok || d.Seconds() != 30 {
		t.Fatal(err)
	}
	// error_degraded.json is exactly what the fake serves.
	var e struct {
		Error string `json:"error"`
		State string `json:"state"`
		Retry int    `json:"retry_after_seconds"`
	}
	if err := json.Unmarshal(golden(t, "error_degraded.json"), &e); err != nil || e.Error != "degraded" || e.State != "degraded" || e.Retry != 30 {
		t.Fatalf("%+v %v", e, err)
	}
}

// TestGoldenMatchesDaemon keeps the copies in sync with the daemon's own
// goldens when the full repository is present.
func TestGoldenMatchesDaemon(t *testing.T) {
	dir := filepath.Join("..", "..", "internal", "domain", "testdata", "wire")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skip("daemon goldens not present")
	}
	for _, e := range entries {
		a, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		b, err := os.ReadFile(filepath.Join("testdata", e.Name()))
		if err != nil || !bytes.Equal(bytes.TrimSpace(a), bytes.TrimSpace(b)) {
			t.Errorf("%s differs from internal/domain golden (%v)", e.Name(), err)
		}
	}
}
