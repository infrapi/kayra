// Package oidc fetches and caches OIDC discovery documents and JWKS key
// sets, and serves Kayra's own aggregated discovery/JWKS endpoints.
package oidc

import (
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
