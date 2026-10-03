package domain

import (
	"fmt"
	"net/http"
	"time"
)

// This file defines the daemon side of the local API wire format (PRD
// section 11). pkg/client deliberately keeps its own copy of these shapes so
// that it imports nothing from internal/ (ADR-C). Both copies are pinned by
// the golden JSON files in internal/domain/testdata/wire, which pkg/client's
// golden tests must also match byte for byte (modulo whitespace). Changing a
// JSON name or an error code is a breaking pkg/client change (semver major).

// API paths.
const (
	PathCredentialPrefix = "/v1/credentials/" // + {provider}
	PathRefreshSuffix    = "/refresh"         // POST PathCredentialPrefix+{provider}+PathRefreshSuffix
	PathStatus           = "/v1/status"
	PathIdentity         = "/v1/identity"
	PathHealthz          = "/healthz"
)

// Wire error codes carried in WireError.Error.
const (
	CodeReauthRequired = "reauth_required" // 401
	CodeRevoked        = "revoked"         // 403
	CodeDegraded       = "degraded"        // 503 with Retry-After
	CodeUnauthorized   = "unauthorized"    // 403, caller not allow-listed
	CodeNotConfigured  = "not_configured"  // 404, unknown or disabled provider
	CodeInternal       = "internal"        // 500
)

// WireCredential is the body of GET /v1/credentials/{provider} and of the
// refresh endpoint. AccessToken is a plain string because it is the secret
// being delivered; only the ipc handler builds it, via NewWireCredential. Its
// formatting methods redact.
type WireCredential struct {
	TokenType   string    `json:"token_type"`
	AccessToken string    `json:"access_token"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Audience    string    `json:"audience"`
}

// NewWireCredential reveals c for delivery to an authenticated caller.
// tokenType is "Bearer" for bearer credentials and the credential kind
// otherwise.
func NewWireCredential(c Credential) WireCredential {
	tt := string(c.Kind)
	if c.Kind == KindBearer {
		tt = "Bearer"
	}
	return WireCredential{TokenType: tt, AccessToken: c.Value.Reveal(), IssuedAt: c.IssuedAt.UTC(), ExpiresAt: c.ExpiresAt.UTC(), Audience: c.Audience()}
}

// String redacts the token.
func (w WireCredential) String() string {
	return fmt.Sprintf("WireCredential{%s, %s, expires %s}", w.TokenType, Redacted, w.ExpiresAt.Format(time.RFC3339))
}

// GoString redacts the token.
func (w WireCredential) GoString() string { return w.String() }

// Format redacts the token for every verb.
func (w WireCredential) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(w.String())) }

// WireProviderStatus is one provider entry of GET /v1/status. It never
// contains a secret; LastError is an error class, not a message.
type WireProviderStatus struct {
	Provider   string     `json:"provider"`
	State      State      `json:"state"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastError  string     `json:"last_error,omitempty"`
	RetryAfter int        `json:"retry_after_seconds,omitempty"`
}

// WireStatus is the body of GET /v1/status.
type WireStatus struct {
	State     State                `json:"state"` // daemon-wide: valid, degraded or revoked
	Providers []WireProviderStatus `json:"providers"`
}

// WireIdentity is the body of GET /v1/identity.
type WireIdentity struct {
	AgentID       string `json:"agent_id"`
	OktaClientID  string `json:"okta_client_id"`
	KID           string `json:"kid"`
	DaemonVersion string `json:"daemon_version"`
	APIVersion    string `json:"api_version"`
}

// APIVersion is the value of WireIdentity.APIVersion.
const APIVersion = "v1"

// WireHealth is the body of GET /healthz.
type WireHealth struct {
	Status string `json:"status"` // "ok"
}

// WireError is the error body of every non-2xx response.
type WireError struct {
	Error             string `json:"error"`
	State             State  `json:"state,omitempty"`
	RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
}

// HTTPStatus maps a wire error code to its HTTP status. Unknown codes are 500.
func HTTPStatus(code string) int {
	switch code {
	case CodeReauthRequired:
		return http.StatusUnauthorized
	case CodeRevoked, CodeUnauthorized:
		return http.StatusForbidden
	case CodeNotConfigured:
		return http.StatusNotFound
	case CodeDegraded:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// CodeForState maps a non-servable state to its wire error code. ok is false
// for servable states, which have no error code.
func CodeForState(s State) (code string, ok bool) {
	switch s {
	case StateReauthRequired:
		return CodeReauthRequired, true
	case StateRevoked:
		return CodeRevoked, true
	case StateDegraded:
		return CodeDegraded, true
	case StateEmpty, StateMinting:
		return CodeDegraded, true // nothing to serve yet: retry later
	default:
		return "", false
	}
}
