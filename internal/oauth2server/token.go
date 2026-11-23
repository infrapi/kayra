package oauth2server

import (
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// tokenError is RFC 6749 section 5.2's error.
func tokenError(c *gin.Context, status int, code, desc string) {
	c.Header("Cache-Control", "no-store")
	c.JSON(status, gin.H{"error": code, "error_description": desc})
}

// token is the token endpoint: authorization_code, refresh_token, for
// public clients, with no client authentication (PKCE and the refresh
// token's rotation stand for it); client_credentials, for Kayra's own
// identities, authenticated by a JWT assertion.
func (s *Server) token(c *gin.Context) {
	if c.PostForm("client_secret") != "" || c.GetHeader("Authorization") != "" {
		tokenError(c, http.StatusUnauthorized, "invalid_client", "clients are public: no client authentication")
		return
	}
	switch c.PostForm("grant_type") {
	case "client_credentials":
		s.clientCredentials(c)
	case "authorization_code":
		s.fromCode(c)
	case "refresh_token":
		s.fromRefresh(c)
	default:
		tokenError(c, http.StatusBadRequest, "unsupported_grant_type", "grant_type is authorization_code, refresh_token or client_credentials")
	}
}

func (s *Server) fromCode(c *gin.Context) {
	var code authCode
	ok, err := s.take("codes", hash(c.PostForm("code")), &code)
	if err != nil {
		tokenError(c, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	switch {
	case !ok:
		tokenError(c, http.StatusBadRequest, "invalid_grant", "the code is unknown, used or expired")
		return
	case c.PostForm("client_id") != code.Client:
		tokenError(c, http.StatusBadRequest, "invalid_grant", "the code is another client's")
		return
	case c.PostForm("redirect_uri") != code.RedirectURI:
		tokenError(c, http.StatusBadRequest, "invalid_grant", "redirect_uri is not the authorization request's")
		return
	case challengeOf(c.PostForm("code_verifier")) != code.Challenge:
		tokenError(c, http.StatusBadRequest, "invalid_grant", "code_verifier does not match the code_challenge")
		return
	case c.PostForm("resource") != "" && c.PostForm("resource") != code.Resource:
		tokenError(c, http.StatusBadRequest, "invalid_target", "resource is not the authorization request's")
		return
	}
	fam := random(16)
	now := s.now()
	if err := s.put("families", fam, family{Client: code.Client, UserID: code.UserID, Created: now, LastUsed: now}, s.ttl.Refresh); err != nil {
		tokenError(c, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	s.issue(c, refreshToken{Family: fam, Client: code.Client, Resource: code.Resource, Scope: code.Scope, Created: now, identity: code.identity}, now)
}

func (s *Server) fromRefresh(c *gin.Context) {
	h := hash(c.PostForm("refresh_token"))
	// one use at a time, across replicas too: a second one sees the
	// token used, a replay, and revokes its session
	release, err := s.lock(c.Request.Context(), h)
	if err != nil {
		tokenError(c, http.StatusServiceUnavailable, "temporarily_unavailable", err.Error())
		return
	}
	defer release()
	var rt refreshToken
	ok, err := s.get("refresh", h, &rt)
	if err != nil {
		tokenError(c, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if !ok {
		tokenError(c, http.StatusBadRequest, "invalid_grant", "the refresh token is unknown, expired or revoked")
		return
	}
	var fam family
	famOK, err := s.get("families", rt.Family, &fam)
	if err != nil {
		tokenError(c, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	switch {
	case rt.Used:
		// a refresh token used twice: stolen, or its client's copy is
		// stale; either way the whole login goes
		_ = s.revokeFamily(rt.Family)
		tokenError(c, http.StatusBadRequest, "invalid_grant", "the refresh token was used already: its login is revoked, log in again")
		return
	case !famOK || fam.Revoked:
		tokenError(c, http.StatusBadRequest, "invalid_grant", "the login is revoked or expired: log in again")
		return
	case c.PostForm("client_id") != rt.Client:
		tokenError(c, http.StatusBadRequest, "invalid_grant", "the refresh token is another client's")
		return
	case c.PostForm("resource") != "" && c.PostForm("resource") != rt.Resource:
		tokenError(c, http.StatusBadRequest, "invalid_target", "resource is not the login's")
		return
	}
	// the user, again: one gone from the directory gets no new token
	if b, ok := s.auth.Backends[rt.Authorization]; ok {
		info, err := b.ResolveUser(rt.UserID, s.ttl.Access)
		if err != nil {
			_ = s.revokeFamily(rt.Family)
			tokenError(c, http.StatusBadRequest, "invalid_grant", "the user: "+err.Error())
			return
		}
		rt.Groups = info.Groups
	}
	rt.Used = true
	fam.LastUsed = s.now()
	if err := s.put("families", rt.Family, fam, fam.Created.Add(s.ttl.Refresh).Sub(s.now())); err != nil {
		tokenError(c, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if err := s.put("refresh", h, rt, fam.Created.Add(s.ttl.Refresh).Sub(s.now())); err != nil {
		tokenError(c, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	rt.Used = false
	s.issue(c, rt, fam.Created)
}

// issue answers an access token and a new refresh token of rt's login,
// which started at started.
func (s *Server) issue(c *gin.Context, rt refreshToken, started time.Time) {
	now := s.now()
	access, err := s.sign(rt, now)
	if err != nil {
		tokenError(c, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	refresh := random(32)
	// unused, it expires after Idle; renewed or not, at the login's end
	ttl := min(s.ttl.Idle, started.Add(s.ttl.Refresh).Sub(s.now()))
	if ttl <= 0 {
		tokenError(c, http.StatusBadRequest, "invalid_grant", "the login expired: log in again")
		return
	}
	if err := s.put("refresh", hash(refresh), rt, ttl); err != nil {
		tokenError(c, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	out := gin.H{"access_token": access, "token_type": "Bearer", "expires_in": int(s.ttl.Access.Seconds()), "refresh_token": refresh}
	if rt.Scope != "" {
		out["scope"] = rt.Scope
	}
	c.JSON(http.StatusOK, out)
}

// sign is an access token: a JWT of the signer's key, its aud the resource.
func (s *Server) sign(rt refreshToken, now time.Time) (string, error) {
	method := jwt.GetSigningMethod(s.signer.Algorithm)
	if method == nil {
		return "", fmt.Errorf("oauth2server: algorithm %q", s.signer.Algorithm)
	}
	claims := jwt.MapClaims{
		"iss":       s.issuer,
		"sub":       rt.UserID,
		"aud":       rt.Resource,
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       now.Add(s.ttl.Access).Unix(),
		"jti":       random(16),
		"client_id": rt.Client,
		"groups":    rt.Groups,
		"sid":       rt.Family, // its session: revoked with it
	}
	if rt.Scope != "" {
		claims["scope"] = rt.Scope
	}
	t := jwt.NewWithClaims(method, claims)
	t.Header["kid"] = s.signer.Kid
	t.Header["typ"] = "at+jwt" // RFC 9068
	return t.SignedString(s.signer.Private)
}

// revoke is RFC 7009: a refresh token revokes its login, an access token
// its jti, until it expires. Always 200, whatever the token.
func (s *Server) revoke(c *gin.Context) {
	token, client := c.PostForm("token"), c.PostForm("client_id")
	var rt refreshToken
	if ok, _ := s.get("refresh", hash(token), &rt); ok {
		if rt.Client == client {
			_ = s.revokeFamily(rt.Family)
		}
		c.Status(http.StatusOK)
		return
	}
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) { return s.signer.Public, nil },
		jwt.WithValidMethods([]string{s.signer.Algorithm}), jwt.WithExpirationRequired()); err == nil {
		jti, _ := claims["jti"].(string)
		cid, _ := claims["client_id"].(string)
		if exp, err := claims.GetExpirationTime(); err == nil && jti != "" && cid == client {
			_ = s.put("revoked", jti, struct{}{}, exp.Sub(s.now())+time.Minute)
		}
	}
	c.Status(http.StatusOK)
}

// revokeFamily revokes a login: its refresh tokens are refused from now on.
func (s *Server) revokeFamily(id string) error {
	var fam family
	ok, err := s.get("families", id, &fam)
	if err != nil || !ok {
		return err
	}
	fam.Revoked = true
	return s.put("families", id, fam, fam.Created.Add(s.ttl.Refresh).Sub(s.now()))
}

// IssueMachineToken signs an access token of one of Kayra's own
// identities, subject (a service account): no login behind it, no
// refresh token, its kind and uid claims the ones the authenticator
// resolves it by (middleware.Authenticator.Machine). It is revoked by
// its jti, at the revocation endpoint with its subject as client_id.
func (s *Server) IssueMachineToken(subject, uid, kind string, audience []string, ttl time.Duration) (string, time.Time, error) {
	method := jwt.GetSigningMethod(s.signer.Algorithm)
	if method == nil {
		return "", time.Time{}, fmt.Errorf("oauth2server: algorithm %q", s.signer.Algorithm)
	}
	now := s.now()
	exp := now.Add(ttl)
	t := jwt.NewWithClaims(method, jwt.MapClaims{
		"iss":       s.issuer,
		"sub":       subject,
		"aud":       audience,
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       exp.Unix(),
		"jti":       random(16),
		"client_id": subject,
		"kind":      kind,
		"uid":       uid,
	})
	t.Header["kid"] = s.signer.Kid
	t.Header["typ"] = "at+jwt" // RFC 9068
	signed, err := t.SignedString(s.signer.Private)
	return signed, time.Unix(exp.Unix(), 0).UTC(), err
}

// Resources are the resources tokens are issued for, Kayra's own first
// when the configuration names none.
func (s *Server) Resources() []string { return slices.Clone(s.cfg.Resources) }

// AllowedResource tells whether a token may be issued for resource: one
// of the resources, or a URL under one.
func (s *Server) AllowedResource(resource string) bool { return s.allowedResource(resource) }
