package okta_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/domain/domaintest"
	"github.com/stainedhead/agent-okta-d/internal/okta"
)

func sprint(f string, v any) string { return fmt.Sprintf(f, v) }

// fakeOkta is an httptest Okta token endpoint.
type fakeOkta struct {
	*httptest.Server
	mu      sync.Mutex
	forms   []url.Values
	paths   []string
	handler func(w http.ResponseWriter, r *http.Request)
}

func newFakeOkta(t *testing.T, h func(w http.ResponseWriter, r *http.Request)) *fakeOkta {
	t.Helper()
	f := &fakeOkta{handler: h}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			f.mu.Lock()
			f.forms = append(f.forms, r.PostForm)
			f.paths = append(f.paths, r.URL.Path)
			f.mu.Unlock()
		}
		f.handler(w, r)
	}))
	t.Cleanup(f.Close)
	return f
}

func okBody(w http.ResponseWriter, token string, expires int) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"token_type":"Bearer","expires_in":%d,"access_token":%q,"scope":"aws.assume"}`, expires, token)
}

func errBody(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":%q,"error_description":"details with TOKEN-LEAK"}`, code)
}

func newClient(t *testing.T, f *fakeOkta, mod ...func(*okta.Config)) (*okta.Client, *domaintest.FakeClock) {
	t.Helper()
	ck := domaintest.NewFakeClock()
	cfg := okta.Config{
		OrgURL:   f.URL,
		ClientID: "0oaAGENT",
		AuthServers: map[string]okta.AuthServer{
			"agents-aws": {ID: "aus1", Audience: "sts.amazonaws.com"},
		},
		Signer: &domaintest.FakeSigner{KID: "kid-1"},
		Clock:  ck,
	}
	for _, m := range mod {
		m(&cfg)
	}
	c, err := okta.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c, ck
}

var awsReq = domain.OktaTokenRequest{AuthServer: "agents-aws", Scope: "aws.assume"}

func TestTokenSuccess(t *testing.T) {
	f := newFakeOkta(t, func(w http.ResponseWriter, _ *http.Request) { okBody(w, "AT-1", 3600) })
	c, ck := newClient(t, f)
	tok, err := c.Token(context.Background(), awsReq)
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken.Reveal() != "AT-1" || tok.TokenType != "Bearer" || tok.Audience != "sts.amazonaws.com" || tok.Scope != "aws.assume" {
		t.Fatalf("%+v", tok)
	}
	if !tok.IssuedAt.Equal(ck.Now()) || !tok.ExpiresAt.Equal(ck.Now().Add(time.Hour)) {
		t.Fatalf("times %v %v", tok.IssuedAt, tok.ExpiresAt)
	}
	if tok.JTI == "" {
		t.Fatal("jti missing")
	}
	if s := fmt.Sprintf("%v %+v %#v", tok, tok, tok); strings.Contains(s, "AT-1") {
		t.Fatal("token leaked via fmt")
	}
	// request shape
	form := f.forms[0]
	if f.paths[0] != "/oauth2/aus1/v1/token" {
		t.Fatalf("path %s", f.paths[0])
	}
	if form.Get("grant_type") != "client_credentials" || form.Get("scope") != "aws.assume" ||
		form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Fatalf("form %v", form)
	}
	if _, ok := form["client_secret"]; ok {
		t.Fatal("client_secret must never be sent")
	}
	jwt := form.Get("client_assertion")
	if strings.Count(jwt, ".") != 2 {
		t.Fatalf("assertion %q", jwt)
	}
	var claims struct{ Aud string }
	decode(t, strings.Split(jwt, ".")[1], &claims)
	if claims.Aud != f.URL+"/oauth2/aus1/v1/token" {
		t.Fatalf("aud %s", claims.Aud)
	}
}

func TestTokenUniqueJTIPerRequest(t *testing.T) {
	f := newFakeOkta(t, func(w http.ResponseWriter, _ *http.Request) { okBody(w, "x", 60) })
	c, _ := newClient(t, f)
	a, _ := c.Token(context.Background(), awsReq)
	b, _ := c.Token(context.Background(), awsReq)
	if a.JTI == b.JTI || a.JTI == "" {
		t.Fatalf("jti %q %q", a.JTI, b.JTI)
	}
}

// ASSUMPTION(A-02): lifetime is always taken from expires_in; short values are honoured as-is.
func TestTokenTTLFromResponseA02(t *testing.T) {
	f := newFakeOkta(t, func(w http.ResponseWriter, _ *http.Request) { okBody(w, "x", 600) })
	c, ck := newClient(t, f)
	tok, err := c.Token(context.Background(), awsReq)
	if err != nil || !tok.ExpiresAt.Equal(ck.Now().Add(10*time.Minute)) {
		t.Fatalf("%v %v", err, tok.ExpiresAt)
	}
}

func TestTokenMalformedResponsesAreProviderErrors(t *testing.T) {
	bodies := map[string]string{
		"not json":      `<html>`,
		"no token":      `{"expires_in":60}`,
		"no expiry":     `{"access_token":"x"}`,
		"zero expiry":   `{"access_token":"x","expires_in":0}`,
		"negative":      `{"access_token":"x","expires_in":-5}`,
		"string expiry": `{"access_token":"x","expires_in":"abc"}`,
	}
	for name, body := range bodies {
		f := newFakeOkta(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })
		c, _ := newClient(t, f)
		_, err := c.Token(context.Background(), awsReq)
		if !errors.Is(err, domain.ErrProvider) || errors.Is(err, domain.ErrAuthDefinitive) || errors.Is(err, domain.ErrTransient) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestTokenDefinitiveErrors(t *testing.T) {
	for _, code := range []string{"invalid_client", "unauthorized_client", "invalid_grant", "access_denied"} {
		for _, status := range []int{400, 401, 403} {
			f := newFakeOkta(t, func(w http.ResponseWriter, _ *http.Request) { errBody(w, status, code) })
			c, _ := newClient(t, f)
			_, err := c.Token(context.Background(), awsReq)
			if !errors.Is(err, domain.ErrAuthDefinitive) {
				t.Errorf("%s/%d: want definitive, got %v", code, status, err)
				continue
			}
			if errors.Is(err, domain.ErrTransient) || domain.ErrorClass(err) != "auth_definitive" {
				t.Errorf("%s/%d: class %s", code, status, domain.ErrorClass(err))
			}
			if strings.Contains(err.Error(), "TOKEN-LEAK") {
				t.Errorf("server text leaked into error: %v", err)
			}
		}
	}
}

func TestTokenOtherRejectionsAreProviderErrors(t *testing.T) {
	for _, code := range []string{"invalid_scope", "invalid_request", "unsupported_grant_type", "Bad Code!"} {
		f := newFakeOkta(t, func(w http.ResponseWriter, _ *http.Request) { errBody(w, 400, code) })
		c, _ := newClient(t, f)
		_, err := c.Token(context.Background(), awsReq)
		if !errors.Is(err, domain.ErrProvider) || errors.Is(err, domain.ErrAuthDefinitive) {
			t.Errorf("%s: got %v", code, err)
		}
	}
	// non-JSON 4xx body
	f := newFakeOkta(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404); _, _ = w.Write([]byte("nope")) })
	c, _ := newClient(t, f)
	if _, err := c.Token(context.Background(), awsReq); !errors.Is(err, domain.ErrProvider) || errors.Is(err, domain.ErrAuthDefinitive) {
		t.Fatalf("got %v", err)
	}
}

func Test5xxIsTransientNeverRevocation(t *testing.T) {
	for _, status := range []int{500, 502, 503, 504} {
		f := newFakeOkta(t, func(w http.ResponseWriter, _ *http.Request) {
			errBody(w, status, "invalid_client") // even with a definitive-looking body
		})
		c, _ := newClient(t, f)
		_, err := c.Token(context.Background(), awsReq)
		if !errors.Is(err, domain.ErrTransient) || errors.Is(err, domain.ErrAuthDefinitive) {
			t.Errorf("%d: got %v", status, err)
		}
	}
}

func Test429RateLimitReset(t *testing.T) {
	var reset func() string
	f := newFakeOkta(t, func(w http.ResponseWriter, _ *http.Request) {
		if v := reset(); v != "" {
			w.Header().Set("X-Rate-Limit-Reset", v)
		}
		w.WriteHeader(429)
	})
	c, ck := newClient(t, f)
	cases := []struct {
		name  string
		reset func() string
		want  time.Duration
		hint  bool
	}{
		{"future", func() string { return strconv.FormatInt(ck.Now().Add(42*time.Second).Unix(), 10) }, 42 * time.Second, true},
		{"past clamps to 1s", func() string { return strconv.FormatInt(ck.Now().Add(-time.Hour).Unix(), 10) }, time.Second, true},
		{"huge clamps to 10m", func() string { return strconv.FormatInt(ck.Now().Add(24*time.Hour).Unix(), 10) }, 10 * time.Minute, true},
		{"garbage", func() string { return "soon" }, 0, false},
		{"absent", func() string { return "" }, 0, false},
	}
	for _, tc := range cases {
		reset = tc.reset
		_, err := c.Token(context.Background(), awsReq)
		if !errors.Is(err, domain.ErrTransient) || errors.Is(err, domain.ErrAuthDefinitive) {
			t.Fatalf("%s: got %v", tc.name, err)
		}
		d, ok := domain.RetryAfter(err)
		if tc.hint && (!ok || d != tc.want) {
			t.Errorf("%s: retry %v %v want %v", tc.name, d, ok, tc.want)
		}
		if !tc.hint && ok && d != 0 {
			t.Errorf("%s: unexpected hint %v", tc.name, d)
		}
	}
}

func Test429RetryAfterHeaderFallback(t *testing.T) {
	f := newFakeOkta(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(429)
	})
	c, _ := newClient(t, f)
	_, err := c.Token(context.Background(), awsReq)
	if d, ok := domain.RetryAfter(err); !ok || d != 7*time.Second {
		t.Fatalf("%v %v", d, ok)
	}
	f2 := newFakeOkta(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "Wed, 21 Oct 2026 07:28:00 GMT")
		w.WriteHeader(429)
	})
	c2, _ := newClient(t, f2)
	_, err = c2.Token(context.Background(), awsReq)
	if d, _ := domain.RetryAfter(err); d != 0 || !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("%v %v", d, err)
	}
}

func TestNetworkErrorsAreTransient(t *testing.T) {
	f := newFakeOkta(t, func(http.ResponseWriter, *http.Request) {})
	c, _ := newClient(t, f)
	f.Close() // connection refused
	_, err := c.Token(context.Background(), awsReq)
	if !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("got %v", err)
	}
}

func TestTimeoutIsTransient(t *testing.T) {
	release := make(chan struct{})
	f := newFakeOkta(t, func(http.ResponseWriter, *http.Request) { <-release })
	defer close(release)
	c, _ := newClient(t, f, func(cfg *okta.Config) { cfg.HTTPClient = &http.Client{Timeout: 50 * time.Millisecond} })
	_, err := c.Token(context.Background(), awsReq)
	if !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("got %v", err)
	}
}

func TestCallerCancellationIsNotTransient(t *testing.T) {
	release := make(chan struct{})
	f := newFakeOkta(t, func(http.ResponseWriter, *http.Request) { <-release })
	defer close(release)
	c, _ := newClient(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	_, err := c.Token(ctx, awsReq)
	if !errors.Is(err, context.Canceled) || errors.Is(err, domain.ErrTransient) {
		t.Fatalf("got %v", err)
	}
}

func TestDoesNotFollowRedirects(t *testing.T) {
	var hits int
	var mu sync.Mutex
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { mu.Lock(); hits++; mu.Unlock() }))
	defer other.Close()
	f := newFakeOkta(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	})
	c, _ := newClient(t, f)
	_, err := c.Token(context.Background(), awsReq)
	if !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("got %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatal("redirect was followed with the client assertion")
	}
}

func TestTokenRequestValidation(t *testing.T) {
	f := newFakeOkta(t, func(w http.ResponseWriter, _ *http.Request) { okBody(w, "x", 60) })
	c, _ := newClient(t, f)
	for name, r := range map[string]domain.OktaTokenRequest{
		"unknown server": {AuthServer: "nope", Scope: "s"},
		"empty scope":    {AuthServer: "agents-aws"},
		"newline scope":  {AuthServer: "agents-aws", Scope: "a\nb"},
	} {
		if _, err := c.Token(context.Background(), r); !errors.Is(err, domain.ErrConfig) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if len(f.forms) != 0 {
		t.Fatal("invalid requests must not reach Okta")
	}
}

func TestSignerFailureDoesNotReachOkta(t *testing.T) {
	f := newFakeOkta(t, func(w http.ResponseWriter, _ *http.Request) { okBody(w, "x", 60) })
	c, _ := newClient(t, f, func(cfg *okta.Config) { cfg.Signer = &domaintest.FakeSigner{Err: errors.New("boom")} })
	if _, err := c.Token(context.Background(), awsReq); !errors.Is(err, domain.ErrProvider) {
		t.Fatalf("got %v", err)
	}
	if len(f.forms) != 0 {
		t.Fatal("request sent")
	}
}

func TestNewClientConfigValidation(t *testing.T) {
	base := func() okta.Config {
		return okta.Config{
			OrgURL: "https://example.okta.com", ClientID: "c",
			AuthServers: map[string]okta.AuthServer{"a": {ID: "x"}},
			Signer:      &domaintest.FakeSigner{}, Clock: domaintest.NewFakeClock(),
		}
	}
	if _, err := okta.NewClient(base()); err != nil {
		t.Fatal(err)
	}
	muts := map[string]func(*okta.Config){
		"empty org":     func(c *okta.Config) { c.OrgURL = "" },
		"relative org":  func(c *okta.Config) { c.OrgURL = "example.okta.com" },
		"http org":      func(c *okta.Config) { c.OrgURL = "http://example.okta.com" },
		"org creds":     func(c *okta.Config) { c.OrgURL = "https://u:p@example.okta.com" },
		"org query":     func(c *okta.Config) { c.OrgURL = "https://example.okta.com?x=1" },
		"no servers":    func(c *okta.Config) { c.AuthServers = nil },
		"empty as id":   func(c *okta.Config) { c.AuthServers = map[string]okta.AuthServer{"a": {}} },
		"as id slash":   func(c *okta.Config) { c.AuthServers = map[string]okta.AuthServer{"a": {ID: "a/b"}} },
		"empty as name": func(c *okta.Config) { c.AuthServers = map[string]okta.AuthServer{"": {ID: "a"}} },
		"no client id":  func(c *okta.Config) { c.ClientID = "" },
		"bad alg":       func(c *okta.Config) { c.Alg = "HS256" },
	}
	for name, m := range muts {
		c := base()
		m(&c)
		if _, err := okta.NewClient(c); !errors.Is(err, domain.ErrConfig) {
			t.Errorf("%s: want ErrConfig, got %v", name, err)
		}
	}
	for _, ok := range []string{"http://127.0.0.1:1", "http://localhost:1", "http://[::1]:1"} {
		c := base()
		c.OrgURL = ok
		if _, err := okta.NewClient(c); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
}

func TestTokenURL(t *testing.T) {
	f := newFakeOkta(t, func(http.ResponseWriter, *http.Request) {})
	c, _ := newClient(t, f, func(cfg *okta.Config) { cfg.OrgURL = f.URL + "/" })
	u, err := c.TokenURL("agents-aws")
	if err != nil || u != f.URL+"/oauth2/aus1/v1/token" {
		t.Fatalf("%v %s", err, u)
	}
	if _, err := c.TokenURL("zzz"); !errors.Is(err, domain.ErrConfig) {
		t.Fatal(err)
	}
}

func dateServer(t *testing.T, date func() string) *fakeOkta {
	return newFakeOkta(t, func(w http.ResponseWriter, _ *http.Request) {
		if d := date(); d != "" {
			w.Header().Set("Date", d)
		}
		w.WriteHeader(http.StatusNotFound) // status is irrelevant for the skew check
	})
}

func TestCheckSkew(t *testing.T) {
	var offset time.Duration
	var ck *domaintest.FakeClock
	f := dateServer(t, func() string { return ck.Now().Add(offset).UTC().Format(http.TimeFormat) })
	var c *okta.Client
	c, ck = newClient(t, f)
	for _, tc := range []struct {
		off     time.Duration
		wantErr bool
	}{
		{0, false}, {10 * time.Second, false}, {-20 * time.Second, false},
		{30 * time.Second, true}, {-31 * time.Second, true}, {5 * time.Minute, true}, {-5 * time.Minute, true},
	} {
		offset = tc.off
		skew, err := c.CheckSkew(context.Background())
		if (err != nil) != tc.wantErr {
			t.Errorf("off %v: err %v", tc.off, err)
		}
		if tc.wantErr && (!errors.Is(err, okta.ErrClockSkew) || !errors.Is(err, domain.ErrProvider)) {
			t.Errorf("off %v: %v", tc.off, err)
		}
		if d := skew - tc.off; d < -time.Second || d > time.Second {
			t.Errorf("off %v: skew %v", tc.off, skew)
		}
	}
}

func TestCheckSkewDateProblems(t *testing.T) {
	for name, d := range map[string]string{"missing": "", "garbage": "yesterday-ish"} {
		f := dateServer(t, func() string { return d })
		// httptest adds its own Date when none is set; force absence by stripping.
		f.handler = func(w http.ResponseWriter, _ *http.Request) {
			w.Header()["Date"] = []string{d}
			w.WriteHeader(200)
		}
		c, _ := newClient(t, f)
		if _, err := c.CheckSkew(context.Background()); !errors.Is(err, domain.ErrProvider) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	f := newFakeOkta(t, func(http.ResponseWriter, *http.Request) {})
	c, _ := newClient(t, f)
	f.Close()
	if _, err := c.CheckSkew(context.Background()); !errors.Is(err, domain.ErrTransient) {
		t.Fatalf("got %v", err)
	}
}
