package domain

import (
	"context"
	"io/fs"
	"log/slog"
	"net"
	"time"
)

// Clock abstracts time so schedulers and expiry logic run on a fake clock.
// Production code uses the monotonic reading from Now for scheduling.
type Clock interface {
	Now() time.Time
	NewTimer(d time.Duration) Timer
}

// Timer mirrors time.Timer.
type Timer interface {
	// C delivers the fire time once.
	C() <-chan time.Time
	// Stop prevents the timer from firing; it reports whether it was active.
	Stop() bool
	// Reset re-arms the timer; it reports whether it had been active.
	Reset(d time.Duration) bool
}

// Signer signs Okta client assertions with a key the agent can never read.
type Signer interface {
	// Sign signs signingInput (the JWS "header.payload" bytes) with algorithm
	// alg ("RS256" or "ES256"; ES256 is ASSUMPTION(A-01)). ES256 signatures
	// are returned in JOSE raw R||S form, so KMS adapters convert from DER
	// (ASSUMPTION(A-10)). kid is the key id registered in Okta.
	Sign(ctx context.Context, alg string, signingInput []byte) (sig []byte, kid string, err error)
	// Public returns the public key as a JWK JSON document, for `enroll`.
	Public() (jwk []byte, err error)
}

// Provider turns the agent's Okta identity (or a stored user credential) into
// one downstream credential form. Providers reach Okta and other providers
// only through Deps.
type Provider interface {
	// Name is the stable provider id used in config, URLs and audit events.
	Name() string
	// Mint obtains a fresh credential. Errors must be classified with the
	// taxonomy in errors.go; user-credential providers return ErrReauthRequired
	// when the stored credential is expired or rejected.
	Mint(ctx context.Context, d Deps) (Credential, error)
	// Sinks lists the files the cache keeps in sync with the credential.
	Sinks() []SinkSpec
	// Revoke is a best-effort withdraw hook; its errors are logged and ignored.
	Revoke(ctx context.Context, c Credential) error
	// Probe verifies c end to end against the provider (used by doctor).
	Probe(ctx context.Context, c Credential) error
}

// Deps is what a Provider may use. It is an interface so provider tests supply
// a fake (domaintest.FakeDeps).
type Deps interface {
	Clock() Clock
	// Okta returns the source of Okta access tokens for the agent.
	Okta() OktaTokenSource
	// Credential returns another provider's current credential (for example
	// the AWS session a github provider needs to read Secrets Manager).
	Credential(ctx context.Context, provider string) (Credential, error)
	// Store returns the configured named secret store.
	Store(name string) (SecretStore, error)
	Logger() *slog.Logger
	Audit() AuditSink
}

// OktaTokenRequest selects an Okta authorization server and scope.
type OktaTokenRequest struct {
	AuthServer string // config name of the authorization server, for example "agents-aws"
	Scope      string
}

// OktaToken is an Okta access token obtained with private_key_jwt.
type OktaToken struct {
	AccessToken SecretString
	TokenType   string
	IssuedAt    time.Time
	ExpiresAt   time.Time // taken from the response, never hardcoded (ASSUMPTION(A-02))
	Audience    string
	Scope       string
	JTI         string // jti of the client assertion that produced it (audit correlation)
}

// OktaTokenSource mints Okta access tokens.
type OktaTokenSource interface {
	Token(ctx context.Context, req OktaTokenRequest) (OktaToken, error)
}

// SecretValue is a stored secret with its version token.
type SecretValue struct {
	Value   SecretString
	Version string
}

// SecretStore is user-credential custody (FR-18). Put is compare-and-set so
// two writers cannot lose a rotated refresh token.
type SecretStore interface {
	// Get returns ErrNotFound for a missing key.
	Get(ctx context.Context, key string) (SecretValue, error)
	// Put stores value if the current version equals expectedVersion ("" means
	// the key must not exist) and returns the new version. A stale
	// expectedVersion yields ErrVersionConflict.
	Put(ctx context.Context, key string, value SecretString, expectedVersion string) (newVersion string, err error)
}

// SinkFormat selects how a credential is rendered into a sink file.
type SinkFormat string

// Sink formats.
const (
	// SinkRaw writes Credential.Value followed by no newline.
	SinkRaw SinkFormat = "raw"
	// SinkRawNL writes Credential.Value followed by one newline.
	SinkRawNL SinkFormat = "raw-nl"
)

// SinkSpec describes one credential file.
type SinkSpec struct {
	Path   string
	Mode   fs.FileMode // for example 0o440
	Owner  string      // user name; "" leaves the daemon user
	Group  string      // group name; "" leaves the daemon group
	Format SinkFormat  // "" means SinkRaw
}

// Sink writes and removes credential files atomically.
type Sink interface {
	// Write replaces the file atomically (temp, fsync, rename).
	Write(ctx context.Context, spec SinkSpec, content SecretString) error
	// Remove deletes the file; a missing file is not an error.
	Remove(ctx context.Context, spec SinkSpec) error
}

// CallerInfo identifies the local process behind a unix-socket connection.
type CallerInfo struct {
	UID    int
	GID    int
	Groups []int // supplementary gids when the platform reports them
	PID    int
	Exe    string // best effort, may be empty
}

// PeerCredReader reads peer credentials from an accepted unix-socket
// connection (SO_PEERCRED on Linux, LOCAL_PEERCRED/LOCAL_PEERPID on macOS).
// Any failure must be treated as deny.
type PeerCredReader interface {
	Read(conn net.Conn) (CallerInfo, error)
}

// AuditSink receives audit events. It must never block the caller for long and
// never fail the operation being audited.
type AuditSink interface {
	Emit(ctx context.Context, e AuditEvent)
}
