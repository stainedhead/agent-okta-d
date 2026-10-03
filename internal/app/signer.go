package app

import (
	"fmt"

	"github.com/stainedhead/agent-okta-d/internal/config"
	"github.com/stainedhead/agent-okta-d/internal/domain"
	filesigner "github.com/stainedhead/agent-okta-d/internal/signer/file"
	"github.com/stainedhead/agent-okta-d/internal/signer/keychain"
	"github.com/stainedhead/agent-okta-d/internal/signer/kms"
	"github.com/stainedhead/agent-okta-d/internal/signer/tpm"
)

// NewSigner selects the signer named by okta.signer.type (file, kms, keychain,
// tpm). Anything the build or platform cannot provide fails closed with
// ErrConfig.
func NewSigner(cfg *config.Config, env Env) (domain.Signer, error) {
	s := cfg.Okta.Signer
	switch s.Type {
	case "file":
		fs, err := filesigner.New(filesigner.Config{Path: s.KeyID, KID: s.KID, PathField: "okta.signer.key_id"})
		if err != nil {
			return nil, err
		}
		if fs.Alg() != s.Alg {
			return nil, domain.NewConfigError("okta.signer.alg", fmt.Sprintf("is %s but the key file holds a %s key", s.Alg, fs.Alg()))
		}
		return fs, nil
	case "kms":
		if env.KMS == nil {
			return nil, domain.NewConfigError("okta.signer.type", "kms is not available in this build (no AWS SDK adapter)")
		}
		api, err := env.KMS(s.KeyID)
		if err != nil {
			return nil, err
		}
		return kms.New(api, s.KeyID, s.KID)
	case "keychain":
		b, err := keychain.Open(s.KeyID)
		if err != nil {
			return nil, err
		}
		return keychain.New(b, s.KID)
	case "tpm":
		b, err := tpm.Open(s.KeyID)
		if err != nil {
			return nil, err
		}
		return tpm.New(b, s.KID)
	}
	return nil, domain.NewConfigError("okta.signer.type", "unknown signer type")
}
