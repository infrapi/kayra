package crypto

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// algForName maps the spec's algorithm strings to jwt/v5's signing methods.
// Only RSA families are supported, matching every example in the spec.
var algForName = map[string]jwt.SigningMethod{
	"RS256": jwt.SigningMethodRS256,
	"RS384": jwt.SigningMethodRS384,
	"RS512": jwt.SigningMethodRS512,
}

// MintSelfJWT signs a JWT with key (which must have a private half,
// i.e. Issuer: true in config), embedding sub and groups as claims and
// expiring after ttl — see cmd/kayra's "token mint" subcommand, the
// one way to get a first bootstrap credential (e.g. carrying the
// sysadmin group, see middleware.SysadminGroupFor) into a brand new
// deployment with no prior session or RBAC object to authenticate
// against the normal way.
func MintSelfJWT(key SigningKey, subject string, groups []string, ttl time.Duration) (string, error) {
	if key.Private == nil {
		return "", fmt.Errorf("selfjwt: key %s has no private half, cannot sign", key.Kid)
	}

	method, ok := algForName[key.Algorithm]
	if !ok {
		return "", fmt.Errorf("selfjwt: unsupported algorithm %q", key.Algorithm)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"sub":    subject,
		"groups": groups,
		"iat":    now.Unix(),
		"exp":    now.Add(ttl).Unix(),
	}
	if len(key.Audiences) > 0 {
		claims["aud"] = key.Audiences
	}

	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = key.Kid

	signed, err := token.SignedString(key.Private)
	if err != nil {
		return "", fmt.Errorf("selfjwt: sign: %w", err)
	}
	return signed, nil
}
