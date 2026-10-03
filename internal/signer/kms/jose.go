// Package kms implements domain.Signer over a narrow KMSAPI interface so no
// cloud SDK is needed in tests. It also hosts the DER to JOSE ECDSA conversion
// and JWK helpers shared by the keychain and tpm signers.
package kms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// es256CoordLen is the byte length of each of R and S for P-256.
const es256CoordLen = 32

// DERToJOSE converts an ASN.1 DER ECDSA signature (SEQUENCE { INTEGER r,
// INTEGER s }, as returned by AWS KMS) to the JOSE raw R||S form of RFC 7518
// section 3.4. coordLen is the curve byte size (32 for ES256).
// ASSUMPTION(A-10): KMS returns DER ECDSA that converts to JOSE raw R and S.
func DERToJOSE(der []byte, coordLen int) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("kms: malformed DER ECDSA signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("kms: trailing data after DER ECDSA signature")
	}
	if sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, errors.New("kms: ECDSA signature components must be positive")
	}
	if sig.R.BitLen() > coordLen*8 || sig.S.BitLen() > coordLen*8 {
		return nil, errors.New("kms: ECDSA signature component too large for curve")
	}
	out := make([]byte, 2*coordLen)
	sig.R.FillBytes(out[:coordLen])
	sig.S.FillBytes(out[coordLen:])
	return out, nil
}

// PublicJWK renders pub as a JWK JSON document for the given alg and kid.
// Supports *rsa.PublicKey (RS256) and P-256 *ecdsa.PublicKey (ES256).
func PublicJWK(pub crypto.PublicKey, alg, kid string) ([]byte, error) {
	b64 := base64.RawURLEncoding.EncodeToString
	m := map[string]string{"use": "sig", "alg": alg}
	if kid != "" {
		m["kid"] = kid
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if alg != "RS256" {
			return nil, fmt.Errorf("kms: RSA key cannot be used for %s", alg)
		}
		m["kty"] = "RSA"
		m["n"] = b64(k.N.Bytes())
		m["e"] = b64(big.NewInt(int64(k.E)).Bytes())
	case *ecdsa.PublicKey:
		if alg != "ES256" || k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("kms: EC key (%s) cannot be used for %s", k.Curve.Params().Name, alg)
		}
		m["kty"] = "EC"
		m["crv"] = "P-256"
		pt, err := k.Bytes() // uncompressed 0x04 || X || Y
		if err != nil || len(pt) != 1+2*es256CoordLen {
			return nil, errors.New("kms: invalid P-256 public key")
		}
		x, y := pt[1:1+es256CoordLen], pt[1+es256CoordLen:]
		m["x"], m["y"] = b64(x), b64(y)
	default:
		return nil, fmt.Errorf("kms: unsupported public key type %T", pub)
	}
	return json.Marshal(m)
}

// AlgFor returns the JOSE alg a public key signs with ("" if unsupported).
func AlgFor(pub crypto.PublicKey) string {
	switch pub.(type) {
	case *rsa.PublicKey:
		return "RS256"
	case *ecdsa.PublicKey:
		return "ES256"
	}
	return ""
}
