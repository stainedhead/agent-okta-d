// Package file implements domain.Signer with a PEM private key held in a local
// file. It is meant for development and tests (PRD FR-2: "file for dev only");
// production deployments use the KMS, Keychain or TPM signers.
package file

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/stainedhead/agent-okta-d/internal/domain"
)

// Supported JWS algorithms.
const (
	AlgRS256 = "RS256"
	// AlgES256 is supported but flagged: ASSUMPTION(A-01) Okta accepts ES256
	// client assertions (to be settled by the M0 spike). RS256 is the default.
	AlgES256 = "ES256"
)

const minRSABits = 2048

// maxKeyFileSize bounds how much of the key file is read.
const maxKeyFileSize = 64 << 10

// Config configures a Signer.
type Config struct {
	Path string // PEM file holding a PKCS#8, PKCS#1 RSA or SEC1 EC (P-256) key
	KID  string // key id registered in Okta
}

// Signer signs with an in-memory copy of the key loaded from a file.
type Signer struct {
	key crypto.Signer
	alg string
	kid string
	jwk []byte
}

var _ domain.Signer = (*Signer)(nil)

// New loads the key file. It refuses a file that is not a regular file or that
// grants any access to group or others (mode & 0o077 != 0), reported as
// domain.ErrPolicy; missing, unparsable or unsupported keys are domain.ErrConfig.
// Errors never contain key bytes.
func New(c Config) (*Signer, error) {
	if c.Path == "" {
		return nil, domain.NewConfigError("okta.signer.path", "key file path is required")
	}
	if c.KID == "" {
		return nil, domain.NewConfigError("okta.signer.kid", "key id is required")
	}
	f, err := os.Open(c.Path)
	if err != nil {
		return nil, domain.NewConfigError("okta.signer.path", "cannot open key file: "+errKind(err))
	}
	defer func() { _ = f.Close() }()
	// Stat the opened descriptor so the permission check and the read refer
	// to the same file (no check/use race).
	st, err := f.Stat()
	if err != nil {
		return nil, domain.NewConfigError("okta.signer.path", "cannot stat key file")
	}
	if !st.Mode().IsRegular() {
		return nil, domain.NewConfigError("okta.signer.path", "key file is not a regular file")
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, domain.Wrap(domain.ErrPolicy, fmt.Errorf("key file %s must not be accessible by group or others (mode %04o)", c.Path, st.Mode().Perm()))
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxKeyFileSize))
	if err != nil {
		return nil, domain.NewConfigError("okta.signer.path", "cannot read key file")
	}
	key, err := parseKey(raw)
	if err != nil {
		return nil, err
	}
	s := &Signer{kid: c.KID}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < minRSABits {
			return nil, domain.NewConfigError("okta.signer.path", "RSA key must be at least 2048 bits")
		}
		s.key, s.alg = k, AlgRS256
		s.jwk, err = rsaJWK(&k.PublicKey, c.KID)
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, domain.NewConfigError("okta.signer.path", "EC key must be P-256")
		}
		s.key, s.alg = k, AlgES256
		s.jwk, err = ecJWK(&k.PublicKey, c.KID)
	default:
		return nil, domain.NewConfigError("okta.signer.path", "unsupported key type")
	}
	if err != nil {
		return nil, domain.NewConfigError("okta.signer.path", "cannot encode public key")
	}
	return s, nil
}

// errKind describes an os error without echoing path details twice.
func errKind(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "file does not exist"
	case errors.Is(err, os.ErrPermission):
		return "permission denied"
	default:
		return "open failed"
	}
}

func parseKey(raw []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, domain.NewConfigError("okta.signer.path", "key file is not PEM encoded")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, domain.NewConfigError("okta.signer.path", "cannot parse private key")
}

// Alg is the JWS algorithm this key signs with (RS256 or ES256).
func (s *Signer) Alg() string { return s.alg }

// Sign implements domain.Signer. alg must match the loaded key type. ES256
// signatures are returned as JOSE raw R||S (ASSUMPTION(A-01) for Okta support).
func (s *Signer) Sign(ctx context.Context, alg string, signingInput []byte) ([]byte, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	if alg != s.alg {
		return nil, "", domain.NewConfigError("okta.signer.alg", "algorithm "+alg+" does not match the key ("+s.alg+")")
	}
	h := sha256.Sum256(signingInput)
	switch k := s.key.(type) {
	case *rsa.PrivateKey:
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
		if err != nil {
			return nil, "", domain.Wrap(domain.ErrProvider, errors.New("rsa signing failed"))
		}
		return sig, s.kid, nil
	case *ecdsa.PrivateKey:
		r, ss, err := ecdsa.Sign(rand.Reader, k, h[:])
		if err != nil {
			return nil, "", domain.Wrap(domain.ErrProvider, errors.New("ecdsa signing failed"))
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		ss.FillBytes(sig[32:])
		return sig, s.kid, nil
	}
	return nil, "", domain.NewConfigError("okta.signer", "unsupported key type")
}

// Public implements domain.Signer and returns the public JWK document.
func (s *Signer) Public() ([]byte, error) { return append([]byte(nil), s.jwk...), nil }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rsaJWK(p *rsa.PublicKey, kid string) ([]byte, error) {
	e := make([]byte, 0, 4)
	for v := p.E; v > 0; v >>= 8 {
		e = append([]byte{byte(v)}, e...)
	}
	return json.Marshal(map[string]string{
		"kty": "RSA", "use": "sig", "alg": AlgRS256, "kid": kid,
		"n": b64(p.N.Bytes()), "e": b64(e),
	})
}

func ecJWK(p *ecdsa.PublicKey, kid string) ([]byte, error) {
	pt, err := p.Bytes() // 0x04 || X || Y, 32 bytes each for P-256
	if err != nil || len(pt) != 65 {
		return nil, errors.New("cannot encode EC public key")
	}
	x, y := pt[1:33], pt[33:]
	return json.Marshal(map[string]string{
		"kty": "EC", "use": "sig", "alg": AlgES256, "kid": kid,
		"crv": "P-256", "x": b64(x), "y": b64(y),
	})
}

// KID returns the configured key id.
func (s *Signer) KID() string { return s.kid }
