package app

import (
	"context"
	"crypto/sha256"
	"sync"

	"github.com/stainedhead/agent-okta-d/internal/config"
	"github.com/stainedhead/agent-okta-d/internal/domain"
	"github.com/stainedhead/agent-okta-d/internal/store/awssm"
	"github.com/stainedhead/agent-okta-d/internal/store/encfile"
	"github.com/stainedhead/agent-okta-d/internal/store/keychain"
)

// Store type names as they appear in the config; they are also the names
// providers pass to Deps.Store.
const (
	StoreAWSSecretsManager = "aws-secretsmanager"
	StoreKeychain          = "keychain"
	StoreFileEncrypted     = "file-encrypted"
)

const (
	keychainService = "agent-okta-d"
	encfileLabel    = "agent-okta-d/encfile/v1"
)

// storeSet builds the configured secret stores lazily, once each.
type storeSet struct {
	cfg    *config.Config
	env    Env
	signer domain.Signer

	mu    sync.Mutex
	built map[string]domain.SecretStore
}

func newStoreSet(cfg *config.Config, env Env, s domain.Signer) *storeSet {
	return &storeSet{cfg: cfg, env: env, signer: s, built: map[string]domain.SecretStore{}}
}

func (s *storeSet) Store(name string) (domain.SecretStore, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.built[name]; ok {
		return st, nil
	}
	st, err := s.build(name)
	if err != nil {
		return nil, err
	}
	s.built[name] = st
	return st, nil
}

func (s *storeSet) build(name string) (domain.SecretStore, error) {
	switch name {
	case StoreAWSSecretsManager:
		if s.env.SecretsManager == nil {
			return nil, domain.NewConfigError("store.type", "aws-secretsmanager is not available in this build (no AWS SDK adapter)")
		}
		api, err := s.env.SecretsManager(s.cfg)
		if err != nil {
			return nil, err
		}
		return awssm.New(api, ""), nil
	case StoreKeychain:
		return keychain.NewNative(keychainService)
	case StoreFileEncrypted:
		return encfile.New(s.encPath(), signerKey{s.signer, s.cfg.Okta.Signer.Alg})
	}
	return nil, domain.NewConfigError("store.type", "unknown store type")
}

// encPath is the file of the file-encrypted store: the first configured path,
// else the daemon state directory.
func (s *storeSet) encPath() string {
	for _, st := range s.storeConfigs() {
		if st.Type == StoreFileEncrypted && st.Path != "" {
			return st.Path
		}
	}
	return stateDir(s.cfg.Agent.ID) + "/secrets.enc"
}

func (s *storeSet) storeConfigs() []config.Store {
	var out []config.Store
	if g := s.cfg.Providers.GitHub; g != nil {
		out = append(out, g.Store)
	}
	if m := s.cfg.Providers.MSGraph; m != nil {
		out = append(out, m.Store)
	}
	return out
}

// signerKey derives the data key of the file-encrypted store from a
// deterministic RS256 signature over a fixed label, so the key never rests on
// disk next to the data. ES256 signatures are randomized and cannot be used.
type signerKey struct {
	signer domain.Signer
	alg    string
}

func (k signerKey) Key(ctx context.Context) ([]byte, error) {
	if k.alg != "RS256" {
		return nil, domain.NewConfigError("store.type", "file-encrypted needs an RS256 signer (ES256 signatures are not deterministic)")
	}
	sig, _, err := k.signer.Sign(ctx, "RS256", []byte(encfileLabel))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(sig)
	return sum[:], nil
}
