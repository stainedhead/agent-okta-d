// Package awssm is the AWS Secrets Manager SecretStore (PRD MG-3, FR-18). It
// talks to a narrow SecretsManagerAPI so no AWS SDK call is needed in tests;
// the SDK-backed adapter is wired in cmd/ using the agent's federated role.
package awssm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// Staging labels used by Put.
const (
	stagePending = "AWSPENDING"
)

// Errors the SecretsManagerAPI implementation must return for the matching
// service conditions, so Store can classify them.
var (
	// ErrResourceNotFound: the secret does not exist (ResourceNotFoundException).
	ErrResourceNotFound = errors.New("secret not found")
	// ErrResourceExists: CreateSecret on an existing name (ResourceExistsException).
	ErrResourceExists = errors.New("secret already exists")
	// ErrStageNotHeld: MoveCurrent named a "from" version that does not hold
	// AWSCURRENT (UpdateSecretVersionStage RemoveFromVersionId mismatch).
	ErrStageNotHeld = errors.New("version does not hold AWSCURRENT")
)

// SecretVersion is one version of a secret's string value.
type SecretVersion struct {
	Value     string
	VersionID string
}

// SecretsManagerAPI is the subset of Secrets Manager the store needs. Values
// are SecretString; all methods address a secret by its name.
type SecretsManagerAPI interface {
	// GetSecretValue returns the AWSCURRENT version.
	GetSecretValue(ctx context.Context, secretID string) (SecretVersion, error)
	// CreateSecret creates a secret with an initial AWSCURRENT version.
	CreateSecret(ctx context.Context, secretID, value, clientRequestToken string) (versionID string, err error)
	// PutSecretValue adds a version carrying only the given staging labels,
	// leaving AWSCURRENT where it is.
	PutSecretValue(ctx context.Context, secretID, value, clientRequestToken string, stages []string) (versionID string, err error)
	// MoveCurrent moves AWSCURRENT from fromVersion to toVersion in one call
	// (UpdateSecretVersionStage with RemoveFromVersionId and MoveToVersionId).
	// It returns ErrStageNotHeld if fromVersion no longer holds AWSCURRENT.
	MoveCurrent(ctx context.Context, secretID, fromVersion, toVersion string) error
}

// Store implements domain.SecretStore over Secrets Manager. The version is the
// Secrets Manager VersionId.
type Store struct {
	api    SecretsManagerAPI
	prefix string
}

var _ domain.SecretStore = (*Store)(nil)

// New returns a Store that maps key k to the secret named prefix+k.
func New(api SecretsManagerAPI, prefix string) *Store { return &Store{api: api, prefix: prefix} }

// newToken returns a fresh idempotency token (32 hex chars, within the
// 32-64 character ClientRequestToken range).
func newToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func classify(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, domain.ErrTransient), errors.Is(err, domain.ErrProvider),
		errors.Is(err, domain.ErrConfig), errors.Is(err, domain.ErrPolicy):
		return err
	}
	return domain.Wrap(domain.ErrProvider, err)
}

func (s *Store) id(key string) (string, error) {
	if key == "" {
		return "", domain.NewConfigError("store.key", "must not be empty")
	}
	return s.prefix + key, nil
}

// Get implements domain.SecretStore.
func (s *Store) Get(ctx context.Context, key string) (domain.SecretValue, error) {
	id, err := s.id(key)
	if err != nil {
		return domain.SecretValue{}, err
	}
	v, err := s.api.GetSecretValue(ctx, id)
	switch {
	case errors.Is(err, ErrResourceNotFound):
		return domain.SecretValue{}, domain.ErrNotFound
	case err != nil:
		return domain.SecretValue{}, classify(err)
	}
	return domain.SecretValue{Value: domain.NewSecret(v.Value), Version: v.VersionID}, nil
}

// Put implements domain.SecretStore. Secrets Manager has no conditional put,
// so an update is a compare-and-set built from two calls: the new value is
// written as an AWSPENDING version, then AWSCURRENT is moved to it naming the
// expected version as the holder to remove. If another writer promoted a
// version first, the move is rejected and Put returns ErrVersionConflict, so a
// rotated refresh token is never silently overwritten. The losing writer's
// orphaned AWSPENDING version is left for Secrets Manager to age out.
//
// UNCONFIRMED (new, not in docs/assumptions.md): that UpdateSecretVersionStage
// rejects RemoveFromVersionId for a version not holding the label. Verify in
// the M0 spike.
func (s *Store) Put(ctx context.Context, key string, value domain.SecretString, expected string) (string, error) {
	id, err := s.id(key)
	if err != nil {
		return "", err
	}
	if expected == "" {
		v, err := s.api.CreateSecret(ctx, id, value.Reveal(), newToken())
		switch {
		case errors.Is(err, ErrResourceExists):
			return "", domain.ErrVersionConflict
		case err != nil:
			return "", classify(err)
		}
		return v, nil
	}
	cur, err := s.api.GetSecretValue(ctx, id)
	switch {
	case errors.Is(err, ErrResourceNotFound):
		return "", domain.ErrVersionConflict
	case err != nil:
		return "", classify(err)
	case cur.VersionID != expected:
		return "", domain.ErrVersionConflict
	}
	nv, err := s.api.PutSecretValue(ctx, id, value.Reveal(), newToken(), []string{stagePending})
	if err != nil {
		return "", classify(err)
	}
	switch err := s.api.MoveCurrent(ctx, id, expected, nv); {
	case errors.Is(err, ErrStageNotHeld):
		return "", domain.ErrVersionConflict
	case err != nil:
		return "", classify(err)
	}
	return nv, nil
}
