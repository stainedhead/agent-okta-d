package client

import (
	"fmt"
	"time"
)

// State is a credential or daemon state as reported by the daemon.
type State string

// States the daemon reports. Unknown values from a newer daemon are passed
// through unchanged, so compare against these constants rather than switching
// exhaustively.
const (
	// StateEmpty means nothing has been minted yet.
	StateEmpty State = "empty"
	// StateMinting means a first credential is being obtained.
	StateMinting State = "minting"
	// StateValid means a credential is cached and servable.
	StateValid State = "valid"
	// StateRefreshing means a servable credential is being renewed.
	StateRefreshing State = "refreshing"
	// StateDegraded means the upstream is failing; the daemon retries.
	StateDegraded State = "degraded"
	// StateRevoked means the daemon was revoked; it serves nothing.
	StateRevoked State = "revoked"
	// StateReauthRequired means a user must re-enroll the provider.
	StateReauthRequired State = "reauth_required"
)

// Credential is the daemon's answer to a credential request.
type Credential struct {
	// TokenType is "Bearer" for bearer tokens, otherwise the credential kind.
	TokenType string `json:"token_type"`
	// AccessToken is the secret itself; it prints as Redacted.
	AccessToken Secret `json:"access_token"`
	// IssuedAt is when the token was issued.
	IssuedAt time.Time `json:"issued_at"`
	// ExpiresAt is when the token stops being valid.
	ExpiresAt time.Time `json:"expires_at"`
	// Audience is the audience the token was minted for.
	Audience string `json:"audience"`
}

// ExpiredAt reports whether the credential has expired at time t.
func (c Credential) ExpiredAt(t time.Time) bool { return !t.Before(c.ExpiresAt) }

// String describes the credential without the token.
func (c Credential) String() string {
	return fmt.Sprintf("Credential{%s, %s, expires %s}", c.TokenType, Redacted, c.ExpiresAt.Format(time.RFC3339))
}

// ProviderStatus is one provider entry of Status. It never contains a secret.
type ProviderStatus struct {
	// Provider is the provider name.
	Provider string `json:"provider"`
	// State is the provider's cache state.
	State State `json:"state"`
	// ExpiresAt is when the cached credential expires, if there is one.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// LastError is an error class (not a message), if the last attempt failed.
	LastError string `json:"last_error,omitempty"`
	// RetryAfterSeconds is the daemon's retry hint in seconds, if any.
	RetryAfterSeconds int `json:"retry_after_seconds,omitempty"`
}

// Status is the daemon-wide and per-provider state.
type Status struct {
	// State is the daemon-wide state: valid, degraded or revoked.
	State State `json:"state"`
	// Providers lists every configured provider.
	Providers []ProviderStatus `json:"providers"`
}

// Identity names the agent identity the daemon acts for.
type Identity struct {
	// AgentID is the agent's identifier.
	AgentID string `json:"agent_id"`
	// OktaClientID is the Okta client id the daemon authenticates as.
	OktaClientID string `json:"okta_client_id"`
	// KID is the key id of the signing key.
	KID string `json:"kid"`
	// DaemonVersion is the daemon's version.
	DaemonVersion string `json:"daemon_version"`
	// APIVersion is the local API version, "v1".
	APIVersion string `json:"api_version"`
}
