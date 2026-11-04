// Package middleware wires authn/authz/crypto together into the two gin
// middlewares Kayra's HTTP API uses: general bearer auth (any configured
// provider, PAT included) and the privileged sysadmin gate for the cluster
// bootstrap endpoints.
package middleware

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/authn"
	"github.com/infrapi/kayra/internal/authz"
	"github.com/infrapi/kayra/internal/config"
	gcrypto "github.com/infrapi/kayra/internal/crypto"
	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/oidc"
	"github.com/infrapi/kayra/internal/store"
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

// SetAuth stores ac as the request's AuthContext, exactly as
// Authenticator.Middleware and SysadminGate do. Exported so other
// packages' tests can build a fixed-identity gate without reaching into
// this package's internals.
func SetAuth(c *gin.Context, ac *AuthContext) {
	c.Set(contextKey, ac)
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

		var ac *AuthContext
		if gcrypto.IsToken(token) {
			ac, err = a.resolvePAT(token)
		} else {
			ac, err = a.resolveJWT(token)
		}
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusUnauthorized, "middleware.Authenticate", ""))
			return
		}

		c.Set(contextKey, ac)
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

	userIDCfg := config.UserIDConfig{From: "token", Field: "sub"}
	remoteURL, proxy := "", ""
	if provider.Remote != nil {
		userIDCfg = provider.Remote.UserID
		remoteURL = provider.Remote.URL
		proxy = provider.Remote.Proxy
	}

	userID, err := authn.ResolveUserID(v, userIDCfg, remoteURL, proxy)
	if err != nil {
		return nil, err
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
		info, err := backend.ResolveUser(userID, v.ExpiresIn(a.DefaultTTL))
		if err != nil {
			return nil, err
		}
		groups, attributes = info.Groups, info.Attributes
	}

	return &AuthContext{
		UserID:        userID,
		Provider:      v.Provider,
		Authorization: provider.Authorization,
		Attributes:    attributes,
		Groups:        groups,
	}, nil
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
		// into the record when this PAT was minted (see tokenapi).
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
		Groups:        groups,
	}, nil
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
