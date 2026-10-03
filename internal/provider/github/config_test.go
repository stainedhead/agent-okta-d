package github

import (
	"errors"
	"testing"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

func validConfig() Config {
	return Config{Mode: ModePAT, Login: "agent-x_acme", StoreName: "aws", SecretID: "agents/x/github"}
}

func TestConfigDefaultsAndValidate(t *testing.T) {
	c, err := validConfig().Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if c.APIBase != DefaultAPIBase || c.ExpiryWarningDays != DefaultExpiryWarningDays || c.RefetchInterval != DefaultRefetchInterval || c.HTTPClient == nil {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestConfigInvalid(t *testing.T) {
	mut := map[string]func(*Config){
		"mode":    func(c *Config) { c.Mode = "x" },
		"login":   func(c *Config) { c.Login = "" },
		"store":   func(c *Config) { c.StoreName = "" },
		"secret":  func(c *Config) { c.SecretID = "" },
		"apibase": func(c *Config) { c.APIBase = "ftp://x" },
		"repo":    func(c *Config) { c.ProbeRepo = "noslash" },
		"warn":    func(c *Config) { c.ExpiryWarningDays = -1 },
	}
	for name, f := range mut {
		c := validConfig()
		f(&c)
		_, err := c.Normalize()
		var ce *domain.ConfigError
		if !errors.Is(err, domain.ErrConfig) || !errors.As(err, &ce) {
			t.Errorf("%s: want ConfigError, got %v", name, err)
		}
	}
}

func TestA06_OAuthClientIDDefault(t *testing.T) {
	// ASSUMPTION(A-06): default to the GitHub CLI public OAuth app.
	c := validConfig()
	c.Mode = ModeOAuthDevice
	n, _ := c.Normalize()
	if n.OAuthClientID != DefaultOAuthClientID || DefaultOAuthClientID == "" {
		t.Fatalf("A-06 default: %q", n.OAuthClientID)
	}
	c.OAuthClientID = "mine"
	n, _ = c.Normalize()
	if n.OAuthClientID != "mine" {
		t.Fatal("override lost")
	}
}

func TestWebBase(t *testing.T) {
	cases := map[string]string{
		"https://api.github.com":            "https://github.com",
		"https://api.github.com/":           "https://github.com",
		"https://ghe.example.com/api/v3":    "https://ghe.example.com",
		"https://api.acme.ghe.com":          "https://acme.ghe.com",
		"http://127.0.0.1:9999":             "http://127.0.0.1:9999",
		"https://other.example.com/custom/": "https://other.example.com",
	}
	for in, want := range cases {
		if got := WebBase(in); got != want {
			t.Errorf("WebBase(%q)=%q want %q", in, got, want)
		}
	}
}
