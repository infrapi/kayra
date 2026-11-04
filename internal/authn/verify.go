// Package authn validates an incoming bearer token (locating the issuing
// provider's key via internal/oidc, verifying signature and iat/exp) and
// resolves the user id it identifies, per each provider's user_id config.
package authn

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/infrapi/kayra/internal/oidc"
)

// Verified is the outcome of successfully verifying a bearer token.
type Verified struct {
	Provider string
	Claims   jwt.MapClaims
	Token    string

	// userinfo caches the provider's userinfo_endpoint response once
	// fetched — see fetchUserinfo. ResolveUserID, ResolveGroups and
	// ResolveAttributes may each need it for the same already-verified
	// token within a single request (a claims-backed authorizations.<name>
	// entry resolves both Groups and Attributes from it, on top of
	// ResolveUserID's own use), and there is no reason to hit the
	// provider's userinfo endpoint more than once for that.
	userinfo map[string]any
}

// Verify parses tokenString as a JWT, locates the provider owning its kid
// via m.FindKey, checks its signature, and enforces iat not in the future
// and exp not in the past — the spec's "obviously then token must contain
// 'iat' and can't be in future, and 'exp' can't be expired."
func Verify(m *oidc.Manager, tokenString string) (*Verified, error) {
	var provider string

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("authn: token has no kid header")
		}

		name, jwk, err := m.FindKey(kid)
		if err != nil {
			return nil, err
		}
		provider = name

		return jwk.PublicKey()
	}, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}))
	if err != nil {
		return nil, fmt.Errorf("authn: verify token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("authn: token is not valid")
	}

	if iat, err := claims.GetIssuedAt(); err == nil && iat != nil && iat.Time.After(time.Now()) {
		return nil, fmt.Errorf("authn: token iat %s is in the future", iat.Time)
	}
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil && exp.Time.Before(time.Now()) {
		return nil, fmt.Errorf("authn: token exp %s is in the past", exp.Time)
	}

	return &Verified{Provider: provider, Claims: claims, Token: tokenString}, nil
}

// fetchUserinfo returns v's provider's userinfo response, fetching and
// caching it on v itself on first use. remoteURL/proxy are always the
// same provider.Remote.URL/Proxy values across every call for one
// request (there is only one discovery document, and one proxy, to
// speak of per provider), so caching unconditionally after the first
// successful fetch — never re-keyed by either — is correct here.
func (v *Verified) fetchUserinfo(remoteURL, proxy string) (map[string]any, error) {
	if v.userinfo != nil {
		return v.userinfo, nil
	}
	doc, err := oidc.FetchDiscovery(remoteURL, proxy)
	if err != nil {
		return nil, err
	}
	if doc.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("authn: provider has no userinfo_endpoint")
	}
	result, err := oidc.FetchUserinfo(doc.UserinfoEndpoint, v.Token, proxy)
	if err != nil {
		return nil, err
	}
	v.userinfo = result
	return result, nil
}

// ExpiresIn returns the duration until the token's exp claim, used as the
// TTL for the resolved-user cache entry. A token with no exp caches for the
// given fallback.
func (v *Verified) ExpiresIn(fallback time.Duration) time.Duration {
	exp, err := v.Claims.GetExpirationTime()
	if err != nil || exp == nil {
		return fallback
	}
	d := time.Until(exp.Time)
	if d <= 0 {
		return fallback
	}
	return d
}
