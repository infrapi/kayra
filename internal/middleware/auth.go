// Package middleware wires authn/authz/crypto together into the gin
// middleware Kayra's HTTP API uses: bearer auth, any configured provider,
// PAT included. What a caller may do is internal/rbac's.
package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/authn"
	"github.com/infrapi/kayra/internal/authz"
	"github.com/infrapi/kayra/internal/config"
	gcrypto "github.com/infrapi/kayra/internal/crypto"
	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/identity"
	"github.com/infrapi/kayra/internal/oidc"
	"github.com/infrapi/kayra/internal/store"
	libauth "github.com/infrapi/lib/pkg/auth"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// contextKey is the gin context key the resolved AuthContext is stored
// under.
const contextKey = "kayra.auth"

// AuthContext is what a successfully authenticated request carries: who
// the caller is, which provider and authorization backend resolved them,
// and their current directory attributes and group membership.
type AuthContext struct {
	UserID        string
	Provider      string
	Authorization string
	Attributes    map[string]string
	Groups        []string
	// Audience and ClientID are a token of Kayra's authorization server's
	// aud and client_id: an app checks the token was issued for it.
	// Empty for any other token.
	Audience []string
	ClientID string
	// Kind is the caller's: identity.KindUser, a human, or one of Kayra's
	// own identities (identity.KindServiceAccount).
	Kind string
	// TokenID is the personal access token's public id the caller
	// authenticated with, "" for any other token.
	TokenID string
	// Scope is that token's, nil when it has none: what the caller may do
	// is what both their rights and it allow.
	Scope *gcrypto.PatScope
}

// GetAuth reads the AuthContext a prior Authenticator.Middleware call set.
func GetAuth(c *gin.Context) (*AuthContext, bool) {
	v, ok := c.Get(contextKey)
	if !ok {
		return nil, false
	}
	ac, ok := v.(*AuthContext)
	return ac, ok
}

// SetAuth stores ac as the request's AuthContext, in the gin context and
// the request's (AuthOf), exactly as Authenticator.Middleware does.
// Exported so other packages' tests can build a fixed-identity gate
// without reaching into this package's internals.
func SetAuth(c *gin.Context, ac *AuthContext) {
	c.Set(contextKey, ac)
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), authKey{}, ac))
}

type authKey struct{}

// AuthOf is the caller of a request, from its context: what SetAuth put
// there, for the handlers of the generated Handlers.
func AuthOf(ctx context.Context) (*AuthContext, bool) {
	ac, ok := ctx.Value(authKey{}).(*AuthContext)
	return ac, ok && ac != nil
}

// Authenticator holds everything the bearer-auth middleware needs: the
// JWKS manager, the business config (to map a provider to its
// authorization backend and user_id rule), one cached authorizer per
// authorizations.<name>, and the keypair PATs are encrypted with.
type Authenticator struct {
	Manager    *oidc.Manager
	Config     *config.Config
	Backends   map[string]*authz.Cached
	Store      store.Store
	Keys       store.Keys
	PatKey     *rsa.PrivateKey
	DefaultTTL time.Duration
	// Revoked tells whether a token of a local provider, Kayra's own, was
	// revoked (internal/oauth2server): its jti, or its session (sid). None
	// is when nil.
	Revoked func(claims map[string]any) (bool, error)
	// Machine resolves a token carrying a kind claim, one of Kayra's own
	// identities (a service account): only the authorization server signs
	// those, so it checks the provider is its signer, then the identity in
	// the store. Such a token is refused when nil.
	Machine func(v *authn.Verified) (*AuthContext, error)
}

// Resolve authenticates token as Middleware does: a PAT, or a JWT of a
// configured provider, its user and groups resolved.
func (a *Authenticator) Resolve(token string) (*AuthContext, error) {
	if gcrypto.IsToken(token) {
		return a.resolvePAT(token)
	}
	return a.resolveJWT(token)
}

// Middleware authenticates every request it wraps: a personal access token
// (crypto.TokenPrefix) is decrypted and looked up, anything else is parsed
// as a JWT and verified against a configured provider's keys. On success
// the resolved AuthContext is stored for downstream handlers; on failure
// the request is aborted with a 401.
func (a *Authenticator) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := extractBearer(c.GetHeader("Authorization"))
		if err != nil {
			httpapi.Fail(c, liberrors.New(http.StatusUnauthorized, "middleware.Authenticate", "%s", err))
			return
		}

		ac, err := a.Resolve(token)
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusUnauthorized, "middleware.Authenticate", ""))
			return
		}
		if !scopeAllows(ac.Scope, c.Request) {
			httpapi.Fail(c, liberrors.New(http.StatusForbidden, "middleware.Authenticate", "%s %s: outside the token's scope", c.Request.Method, c.Request.URL.Path).
				WithSolution("use a token whose scope covers it, or log in"))
			return
		}

		SetAuth(c, ac)
		c.Next()
	}
}

func (a *Authenticator) resolveJWT(token string) (*AuthContext, error) {
	v, err := authn.Verify(a.Manager, token)
	if err != nil {
		return nil, err
	}

	provider, ok := a.Config.Authentifications[v.Provider]
	if !ok {
		return nil, fmt.Errorf("middleware: unknown provider %q", v.Provider)
	}
	if len(provider.Local) > 0 && a.Revoked != nil {
		revoked, err := a.Revoked(v.Claims)
		if err != nil {
			return nil, err
		}
		if revoked {
			return nil, fmt.Errorf("middleware: the token is revoked")
		}
	}

	if _, ok := v.Claims["kind"]; ok {
		if a.Machine == nil || len(provider.Local) == 0 {
			return nil, fmt.Errorf("middleware: a token of one of Kayra's own identities, which this server does not issue")
		}
		return a.Machine(v)
	}

	return a.ResolveVerified(v, nil)
}

// ResolveVerified resolves a verified token's user, as its provider's
// user_id says (or userID, when set), then their groups and attributes
// from its authorization backend. The authorization server
// (internal/oauth2server) gives it the ID token it checked at a login.
func (a *Authenticator) ResolveVerified(v *authn.Verified, userID *config.UserIDConfig) (*AuthContext, error) {
	provider, ok := a.Config.Authentifications[v.Provider]
	if !ok {
		return nil, fmt.Errorf("middleware: unknown provider %q", v.Provider)
	}
	userIDCfg := config.UserIDConfig{From: "token", Field: "sub"}
	remoteURL, proxy := "", ""
	if provider.Remote != nil {
		userIDCfg = provider.Remote.UserID
		remoteURL = provider.Remote.URL
		proxy = provider.Remote.Proxy
	}
	if userID != nil {
		userIDCfg = *userID
	}

	user, err := authn.ResolveUserID(v, userIDCfg, remoteURL, proxy)
	if err != nil {
		return nil, err
	}
	if identity.IsReserved(user) {
		return nil, fmt.Errorf("middleware: user id %q: the %q prefix is Kayra's own identities'", user, identity.Reserved)
	}

	authzCfg, ok := a.Config.Authorizations[provider.Authorization]
	if !ok {
		return nil, fmt.Errorf("middleware: no authorization backend %q", provider.Authorization)
	}

	var groups []string
	var attributes map[string]string
	if authzCfg.Claims != nil {
		// Claims-backed: no directory to look userID up in — Groups and
		// Attributes are pulled directly out of this same already-verified
		// token/userinfo instead, so a.Backends is never consulted.
		groups, err = authn.ResolveGroups(v, authzCfg.Claims.From, authzCfg.Claims.GroupsField, authzCfg.Claims.GroupsFilter, remoteURL, proxy)
		if err != nil {
			return nil, err
		}
		attributes, err = authn.ResolveAttributes(v, authzCfg.Claims.From, authzCfg.Claims.UserAttributes, remoteURL, proxy)
		if err != nil {
			return nil, err
		}
	} else {
		backend, ok := a.Backends[provider.Authorization]
		if !ok {
			return nil, fmt.Errorf("middleware: no authorization backend %q", provider.Authorization)
		}
		info, err := backend.ResolveUser(user, v.ExpiresIn(a.DefaultTTL))
		if err != nil {
			return nil, err
		}
		groups, attributes = info.Groups, info.Attributes
	}

	ac := &AuthContext{
		UserID:        user,
		Provider:      v.Provider,
		Authorization: provider.Authorization,
		Attributes:    attributes,
		Groups:        humanGroups(groups),
		Kind:          identity.KindUser,
	}
	// a token of Kayra's authorization server: one of its own, issued to a
	// client
	if cid, _ := v.Claims["client_id"].(string); cid != "" && len(provider.Local) > 0 {
		aud, _ := v.Claims.GetAudience()
		ac.Audience, ac.ClientID = aud, cid
	}
	return ac, nil
}

func (a *Authenticator) resolvePAT(token string) (*AuthContext, error) {
	data, err := a.Store.Get(a.Keys.PatToken(gcrypto.HashToken(token)))
	if err != nil {
		if err == store.ErrNotFound {
			return nil, fmt.Errorf("middleware: token not found")
		}
		return nil, err
	}

	record, err := gcrypto.DecryptRecord(a.PatKey, data)
	if err != nil {
		return nil, err
	}
	if identity.IsReserved(record.UserID) {
		return nil, fmt.Errorf("middleware: a personal access token of %q, one of Kayra's own identities", record.UserID)
	}
	now := time.Now()
	if record.ExpiresAt == 0 || now.Unix() >= record.ExpiresAt {
		return nil, fmt.Errorf("middleware: the token expired")
	}
	a.touchPAT(record, now)

	authzCfg, ok := a.Config.Authorizations[record.Authorization]
	if !ok {
		return nil, fmt.Errorf("middleware: no authorization backend %q", record.Authorization)
	}

	var groups []string
	var attributes map[string]string
	if authzCfg.Claims != nil {
		// Claims-backed: there is no live session left to re-query by
		// bare user id (the original token is long gone by the time this
		// PAT gets used), so this is the one case Groups/Attributes are
		// NOT resolved live — they're whatever RegisterRoutes snapshotted
		// into the record when this PAT was minted (see rbac.Server.CreateToken).
		groups, attributes = record.SnapshotGroups, record.SnapshotAttributes
	} else {
		backend, ok := a.Backends[record.Authorization]
		if !ok {
			return nil, fmt.Errorf("middleware: no authorization backend %q", record.Authorization)
		}
		info, err := backend.ResolveUser(record.UserID, a.DefaultTTL)
		if err != nil {
			return nil, err
		}
		groups, attributes = info.Groups, info.Attributes
	}

	return &AuthContext{
		UserID:        record.UserID,
		Provider:      record.Provider,
		Authorization: record.Authorization,
		Attributes:    attributes,
		Groups:        humanGroups(groups),
		Kind:          identity.KindUser,
		TokenID:       record.ID,
		Scope:         record.Scope,
	}, nil
}

// touchPAT records when a token was last used, at most once an hour: a
// write per request would be one too many. Best effort: a failure leaves
// the date older.
func (a *Authenticator) touchPAT(record gcrypto.PatRecord, now time.Time) {
	key := a.Keys.PatIndex(record.UserID, record.ID)
	var e gcrypto.PatIndexEntry
	if err := store.GetJSON(a.Store, key, &e); err != nil || now.Unix()-e.LastUsedAt < 3600 {
		return
	}
	e.LastUsedAt = now.Unix()
	if data, err := json.Marshal(e); err == nil {
		_ = a.Store.PutTTL(key, data, time.Until(time.Unix(e.ExpiresAt, 0)))
	}
}

// scopeAllows tells whether a token's scope lets it send r: an API
// request whose api and verb it grants, read as /check reads them; the
// authorization check itself, which decides with the scope (rbac's
// /check); userinfo; the discovery, GET /apis. Anything else, sessions say, is no scoped token's.
func scopeAllows(scope *gcrypto.PatScope, r *http.Request) bool {
	if scope == nil {
		return true
	}
	// who it is, and the discovery of the APIs (what a client resolves a
	// resource with before any request)
	if r.URL.Path == "/oauth2/userinfo" || (r.Method == http.MethodGet && (r.URL.Path == "/apis" || r.URL.Path == "/apis/")) {
		return true
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/apis/")
	if !ok {
		return false
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 3 {
		return false
	}
	api, resource := parts[0], parts[2:]
	if strings.HasPrefix(api, "authorization.") && len(resource) == 1 && resource[0] == "check" {
		return true
	}
	if resource[0] == "namespaces" && len(resource) > 2 {
		resource = resource[2:]
	}
	_, hasID, err := libauth.ParseResource(strings.Join(resource, "/"))
	if err != nil {
		return false
	}
	verb, err := libauth.VerbFor(r.Method, hasID)
	return err == nil && scope.Allows(api, verb)
}

// humanGroups are a human's resolved groups without the reserved ones: a
// directory group named like Kayra's own (system:serviceaccounts:core)
// never makes its members one of its service accounts.
func humanGroups(groups []string) []string {
	return slices.DeleteFunc(slices.Clone(groups), identity.IsReserved)
}

func extractBearer(header string) (string, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", fmt.Errorf("missing bearer token")
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", fmt.Errorf("empty bearer token")
	}
	return token, nil
}
