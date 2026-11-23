// Package oidc fetches and caches OIDC discovery documents and JWKS key
// sets, and serves Kayra's own aggregated discovery/JWKS endpoints.
package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

// JWK is one entry of a JSON Web Key Set, as returned by a provider's
// jwks_uri and by Kayra's own /oauth2/discovery/keys.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	// Crv, X and Y are an EC key's (kty EC): P-256, P-384, P-521.
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	// D is a private key's: refused wherever a public key is expected.
	D string `json:"d,omitempty"`
	// InfraPIAuthProvider names the authentifications.<name> entry this key
	// belongs to, per the spec's extension field on every key.
	InfraPIAuthProvider string `json:"infrapi_auth_provider"`
}

// JWKSet is the top-level shape of a JWKS document.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// PublicKey decodes an RSA public key out of the JWK's n/e members.
func (k JWK) PublicKey() (*rsa.PublicKey, error) {
	if k.Kty != "RSA" {
		return nil, fmt.Errorf("jwk %s: unsupported kty %q", k.Kid, k.Kty)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("jwk %s: decode n: %w", k.Kid, err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("jwk %s: decode e: %w", k.Kid, err)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

// NewJWK encodes pub as a JWK under kid/alg, tagged with provider.
func NewJWK(provider, kid, alg string, pub *rsa.PublicKey) JWK {
	return JWK{
		Kty:                 "RSA",
		Kid:                 kid,
		Use:                 "sig",
		Alg:                 alg,
		N:                   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:                   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		InfraPIAuthProvider: provider,
	}
}

// Key decodes the JWK's public key, RSA or EC: what a client's or a
// federated issuer's token is verified with.
func (k JWK) Key() (any, error) {
	if k.Kty == "RSA" {
		return k.PublicKey()
	}
	if k.Kty != "EC" {
		return nil, fmt.Errorf("jwk %s: unsupported kty %q, RSA or EC", k.Kid, k.Kty)
	}
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("jwk %s: unsupported crv %q", k.Kid, k.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("jwk %s: decode x: %w", k.Kid, err)
	}
	y, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("jwk %s: decode y: %w", k.Kid, err)
	}
	// the uncompressed point, 0x04 || x || y, each coordinate its curve's size
	size := (curve.Params().BitSize + 7) / 8
	if len(x) > size || len(y) > size {
		return nil, fmt.Errorf("jwk %s: a coordinate longer than %s's", k.Kid, k.Crv)
	}
	point := make([]byte, 1+2*size)
	point[0] = 4
	copy(point[1+size-len(x):1+size], x)
	copy(point[1+2*size-len(y):], y)
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, fmt.Errorf("jwk %s: %w", k.Kid, err)
	}
	return pub, nil
}
