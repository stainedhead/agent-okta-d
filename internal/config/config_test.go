package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

const minimal = `
agent: {id: a1}
okta:
  org_url: https://EXAMPLE.okta.com
  client_id: 0oaX
  signer: {type: file, key_id: /etc/agentd/key.pem, kid: k1}
ipc: {allow_gids: [agent]}
`

func mustErrConfig(t *testing.T, err error, field string) {
	t.Helper()
	if !errors.Is(err, domain.ErrConfig) {
		t.Fatalf("want ErrConfig, got %v", err)
	}
	if domain.ExitCode(err) != 78 {
		t.Fatalf("exit code %d", domain.ExitCode(err))
	}
	if !strings.Contains(err.Error(), field) {
		t.Fatalf("error %q does not name %q", err, field)
	}
}

func TestLoadSample(t *testing.T) {
	c, err := Load("testdata/sample.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.Agent.ID != "sdlc-reviewer-01" || c.Providers.AWS.RoleSessionName != "sdlc-reviewer-01" ||
		c.Providers.MSGraph.Scopes[1] != "offline_access" || c.IPC.AllowGIDs[0] != "agent" ||
		c.Providers.Atlassian.Sink.Mode != "0440" || c.Providers.GitHub.Store.Type != "aws-secretsmanager" {
		t.Fatalf("unexpected parse: %+v", c)
	}
	if len(c.Warnings()) != 0 {
		t.Fatalf("warnings: %v", c.Warnings())
	}
}

func TestDefaults(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if c.Okta.Signer.Alg != "RS256" || c.Refresh.Fraction != 0.5 || c.Refresh.Jitter != 0.05 ||
		c.Refresh.MinMarginSeconds != 120 || c.Log.Level != "info" || c.Log.Format != "json" ||
		c.Log.Destination != "stderr" || !strings.HasSuffix(c.IPC.Socket, "/a1/agentd.sock") {
		t.Fatalf("defaults: %+v", c)
	}
	if c.Providers.AWS != nil || c.Providers.GitHub != nil {
		t.Fatal("absent providers must stay nil")
	}
}

func TestProviderDefaults(t *testing.T) {
	y := minimal + `
providers:
  aws: {authorization_server: s, scope: x, role_arn: r, region: us-east-1}
  github: {mode: pat, login: l, store: {type: keychain, secret_id: s}}
  servicenow: {instance_url: "https://EXAMPLE.service-now.com", authorization_server: s, scope: x}
  msgraph: {tenant_id: t, app_client_id: c, upn: u, scopes: [a], store: {type: keychain, secret_id: s}}
  atlassian: {source: aws-secretsmanager, secret_id: s}
`
	c, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	p := c.Providers
	if p.AWS.FileMode != "0440" || p.AWS.RoleSessionName != "a1" || !strings.HasSuffix(p.AWS.TokenFile, "/a1/aws-web-identity.jwt") ||
		p.GitHub.APIBase != "https://api.github.com" || p.GitHub.ExpiryWarningDays != 30 ||
		p.ServiceNow.MinTTLSeconds != 120 || p.MSGraph.ReauthWarningDays != 14 ||
		p.Atlassian.Type != "secret" || p.Atlassian.Sink.Mode != "0440" || !strings.HasSuffix(p.Atlassian.Sink.File, "/a1/atlassian.key") {
		t.Fatalf("provider defaults: %+v", p)
	}
}

func TestWarningsAssumptions(t *testing.T) {
	// ASSUMPTION(A-01) and ASSUMPTION(A-06) surface as warnings.
	y := strings.Replace(minimal, "kid: k1}", "kid: k1, alg: ES256}", 1) + `
providers:
  github: {mode: oauth_device, login: l, store: {type: keychain, secret_id: s}}
`
	c, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	w := strings.Join(c.Warnings(), "\n")
	if !strings.Contains(w, "A-01") || !strings.Contains(w, "A-06") {
		t.Fatalf("warnings: %q", w)
	}
}

func TestLoadErrors(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	mustErrConfig(t, err, "not found")
	d := t.TempDir()
	_, err = Load(d) // directory: read error
	mustErrConfig(t, err, "config file")
	p := filepath.Join(d, "denied.yaml")
	if werr := os.WriteFile(p, []byte(minimal), 0o000); werr != nil {
		t.Fatal(werr)
	}
	if os.Geteuid() != 0 {
		_, err = Load(p)
		mustErrConfig(t, err, "permission denied")
	}
}

func TestParseErrors(t *testing.T) {
	_, err := Parse(nil)
	mustErrConfig(t, err, "empty")
	_, err = Parse([]byte("agent: [unclosed"))
	mustErrConfig(t, err, "invalid YAML")
	_, err = Parse([]byte("bogus_field: 1"))
	mustErrConfig(t, err, "invalid YAML")
	// Type error must not echo the offending value.
	_, err = Parse([]byte("refresh: {fraction: SECRETVALUE}"))
	mustErrConfig(t, err, "invalid YAML")
	if strings.Contains(err.Error(), "SECRETVALUE") {
		t.Fatalf("value echoed: %v", err)
	}
	if !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("no position: %v", err)
	}
}

func TestValidationFields(t *testing.T) {
	prov := func(s string) string { return minimal + "providers:\n" + s }
	cases := []struct{ name, yaml, field string }{
		{"no agent id", strings.Replace(minimal, "id: a1", "id: ''", 1), "agent.id"},
		{"bad agent id", strings.Replace(minimal, "id: a1", "id: a/../b", 1), "agent.id"},
		{"dot agent id", strings.Replace(minimal, "id: a1", "id: .hid", 1), "agent.id"},
		{"http org", strings.Replace(minimal, "https://EXAMPLE", "http://EXAMPLE", 1), "okta.org_url"},
		{"no org", strings.Replace(minimal, "org_url: https://EXAMPLE.okta.com", "org_url: ''", 1), "okta.org_url"},
		{"bad url", strings.Replace(minimal, "https://EXAMPLE.okta.com", "https://%zz", 1), "okta.org_url"},
		{"no client", strings.Replace(minimal, "client_id: 0oaX", "client_id: ''", 1), "okta.client_id"},
		{"bad signer", strings.Replace(minimal, "type: file", "type: usb", 1), "okta.signer.type"},
		{"bad alg", strings.Replace(minimal, "kid: k1", "kid: k1, alg: HS256", 1), "okta.signer.alg"},
		{"no kid", strings.Replace(minimal, ", kid: k1", "", 1), "okta.signer.kid"},
		{"no key id", strings.Replace(minimal, ", key_id: /etc/agentd/key.pem", "", 1), "okta.signer.key_id"},
		{"no gids", strings.Replace(minimal, "[agent]", "[]", 1), "ipc.allow_gids"},
		{"blank gid", strings.Replace(minimal, "[agent]", "[' ']", 1), "ipc.allow_gids[0]"},
		{"bad fraction", minimal + "refresh: {fraction: 1.5}", "refresh.fraction"},
		{"neg fraction", minimal + "refresh: {fraction: -0.1}", "refresh.fraction"},
		{"bad jitter", minimal + "refresh: {jitter: 1}", "refresh.jitter"},
		{"neg margin", minimal + "refresh: {min_margin_seconds: -1}", "refresh.min_margin_seconds"},
		{"bad level", minimal + "log: {level: trace}", "log.level"},
		{"bad format", minimal + "log: {format: xml}", "log.format"},
		{"aws missing role", prov("  aws: {authorization_server: s, scope: x, region: r}"), "providers.aws.role_arn"},
		{"aws bad mode", prov("  aws: {authorization_server: s, scope: x, role_arn: r, region: r, file_mode: '0999'}"), "providers.aws.file_mode"},
		{"aws long mode", prov("  aws: {authorization_server: s, scope: x, role_arn: r, region: r, file_mode: '00440'}"), "providers.aws.file_mode"},
		{"gh bad mode", prov("  github: {mode: x, login: l, store: {type: keychain, secret_id: s}}"), "providers.github.mode"},
		{"gh bad store", prov("  github: {mode: pat, login: l, store: {type: nfs, secret_id: s}}"), "providers.github.store.type"},
		{"gh no secret", prov("  github: {mode: pat, login: l, store: {type: keychain}}"), "providers.github.store.secret_id"},
		{"gh http", prov("  github: {api_base: 'http://x', mode: pat, login: l, store: {type: keychain, secret_id: s}}"), "providers.github.api_base"},
		{"gh neg days", prov("  github: {expiry_warning_days: -1, mode: pat, login: l, store: {type: keychain, secret_id: s}}"), "providers.github.expiry_warning_days"},
		{"snow no url", prov("  servicenow: {authorization_server: s, scope: x}"), "providers.servicenow.instance_url"},
		{"snow neg ttl", prov("  servicenow: {instance_url: 'https://x', authorization_server: s, scope: x, min_ttl_seconds: -5}"), "providers.servicenow.min_ttl_seconds"},
		{"graph no upn", prov("  msgraph: {tenant_id: t, app_client_id: c, scopes: [a], store: {type: keychain, secret_id: s}}"), "providers.msgraph.upn"},
		{"graph no scopes", prov("  msgraph: {tenant_id: t, app_client_id: c, upn: u, store: {type: keychain, secret_id: s}}"), "providers.msgraph.scopes"},
		{"graph bad store", prov("  msgraph: {tenant_id: t, app_client_id: c, upn: u, scopes: [a], store: {type: x, secret_id: s}}"), "providers.msgraph.store.type"},
		{"graph neg days", prov("  msgraph: {tenant_id: t, app_client_id: c, upn: u, scopes: [a], reauth_warning_days: -1, store: {type: keychain, secret_id: s}}"), "providers.msgraph.reauth_warning_days"},
		{"atl bad type", prov("  atlassian: {type: x, source: aws-secretsmanager, secret_id: s}"), "providers.atlassian.type"},
		{"atl bad source", prov("  atlassian: {source: vault, secret_id: s}"), "providers.atlassian.source"},
		{"atl no secret", prov("  atlassian: {source: aws-secretsmanager}"), "providers.atlassian.secret_id"},
		{"atl bad mode", prov("  atlassian: {source: aws-secretsmanager, secret_id: s, sink: {mode: '9'}}"), "providers.atlassian.sink.mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			mustErrConfig(t, err, tc.field)
		})
	}
}

func TestSecretValuesNotEchoed(t *testing.T) {
	y := strings.Replace(minimal, "kid: k1", "kid: k1, alg: s3cr3t-alg", 1)
	_, err := Parse([]byte(y))
	mustErrConfig(t, err, "okta.signer.alg")
	if strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("value echoed: %v", err)
	}
}

func TestParseMode(t *testing.T) {
	for _, s := range []string{"0440", "640", "0600", "0"} {
		if _, ok := parseMode(s); !ok {
			t.Errorf("%q should parse", s)
		}
	}
	for _, s := range []string{"", "8", "1777", "abcd", "-1"} {
		if _, ok := parseMode(s); ok {
			t.Errorf("%q should fail", s)
		}
	}
}

func TestRuntimeDir(t *testing.T) {
	if got := runtimeDir("x"); got != "/run/agentd/x/" && got != "/var/run/agentd/x/" {
		t.Fatal(got)
	}
}
