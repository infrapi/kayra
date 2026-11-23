// Package apiserver wires every other internal package onto the gin
// engine infrapi/lib's pkg/server builds, so main only has to call
// Build once.
package apiserver

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/authn"
	"github.com/infrapi/kayra/internal/authz"
	"github.com/infrapi/kayra/internal/catalog"
	gconfig "github.com/infrapi/kayra/internal/config"
	gcrypto "github.com/infrapi/kayra/internal/crypto"
	"github.com/infrapi/kayra/internal/discovery"
	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/identity"
	"github.com/infrapi/kayra/internal/middleware"
	"github.com/infrapi/kayra/internal/oauth2server"
	"github.com/infrapi/kayra/internal/oidc"
	"github.com/infrapi/kayra/internal/rbac"
	"github.com/infrapi/kayra/internal/store"
	"github.com/infrapi/kayra/internal/tokenapi"
	libconfig "github.com/infrapi/lib/pkg/config"
	liberrors "github.com/infrapi/lib/pkg/errors"
	libserver "github.com/infrapi/lib/pkg/server"
)

// DefaultUserCacheTTL is used when a verified token carries no exp (a self
// JWT issued without one, say); normally the TTL is the token's own
// remaining lifetime, per the spec's "cache ... for 'exp' duration."
const DefaultUserCacheTTL = time.Hour

// Build loads Kayra's business config, opens its store, and returns a
// ready-to-run gin engine: the infrapi/lib discovery/metrics/docs
// endpoints plus every Kayra route.
func Build(appCfg *libconfig.AppConfig, cfg *gconfig.Config, opts ...Option) (*gin.Engine, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	// Without this, posting a Role-shaped body (or any mismatched
	// resource) to a Group endpoint silently drops the fields Group
	// doesn't have and returns a confusing partial object instead of an
	// error — exactly the "why does authorization show up" surprise this
	// closes off.
	gin.EnableJsonDecoderDisallowUnknownFields()

	_, dbBackend, err := cfg.ActiveDatabase()
	if err != nil {
		return nil, err
	}
	s, keys, err := store.New(dbBackend)
	if err != nil {
		return nil, fmt.Errorf("apiserver: open store: %w", err)
	}

	// $region and $platform, this instance's, in what tokens must carry
	cfg.RenderClaims(appCfg.AppRegion, appCfg.AppPlatform)
	manager, err := oidc.NewManager(s, keys, cfg)
	if err != nil {
		return nil, fmt.Errorf("apiserver: build oidc manager: %w", err)
	}

	backends := make(map[string]*authz.Cached, len(cfg.Authorizations))
	for name, authzCfg := range cfg.Authorizations {
		if authzCfg.Claims != nil {
			// Claims-backed: resolved directly from each caller's own
			// already-verified token/userinfo (see middleware.resolveJWT/
			// resolvePAT), never through this map — there is no network
			// backend to build at all.
			continue
		}
		backend, err := authz.New(authzCfg)
		if err != nil {
			return nil, fmt.Errorf("apiserver: build authorization backend %s: %w", name, err)
		}
		backends[name] = authz.NewCached(backend, s, keys, name)
	}

	patKey, err := gcrypto.LoadOrCreatePatKeypair(s, keys, cfg.Tokens.Pat)
	if err != nil {
		return nil, fmt.Errorf("apiserver: load pat keypair: %w", err)
	}

	authenticator := &middleware.Authenticator{
		Manager:    manager,
		Config:     cfg,
		Backends:   backends,
		Store:      s,
		Keys:       keys,
		PatKey:     patKey,
		DefaultTTL: DefaultUserCacheTTL,
	}

	// Empty cfg.App.APIDomain falls back to "infrapi.io" — every API
	// group internal/rbac and internal/catalog mount, and every
	// Role.Rules entry an operator authors, is "<group>.<domain>", so
	// this must be resolved before either package registers a single
	// route.
	apiDomain := cfg.App.APIDomain
	if apiDomain == "" {
		apiDomain = "infrapi.io"
	}
	rbac.SetAPIDomain(apiDomain)
	catalog.SetAPIDomain(apiDomain)

	// infrapi/lib serves its own endpoints (health, metrics, metadata,
	// OpenAPI, docs) under each of Kayra's groups, about that group's
	// routes: /apis/catalog.<domain>/v1/-/openapi.json. They answer
	// without a token.
	engine, err := libserver.NewServerGin(appCfg, Roots())
	if err != nil {
		return nil, fmt.Errorf("apiserver: build gin engine: %w", err)
	}

	baseURL := appCfg.AppUrl

	// Unknown paths get the same problem+json body as every other error
	// instead of gin's plain-text "404 page not found".
	// the audit of Kayra's own routes, once served: before any of them is
	// registered, for gin to put it in front of each
	checkPath := "/apis/" + rbac.AuthorizationAPI + "/v1/check"
	engine.Use(auditRequests(o.auditor, Roots(), checkPath))

	engine.NoRoute(func(c *gin.Context) {
		httpapi.Fail(c, liberrors.New(http.StatusNotFound, "apiserver.NoRoute", "no route for %s %s", c.Request.Method, c.Request.URL.Path))
	})

	oidc.RegisterRoutes(engine, manager, baseURL)
	// /.well-known/kayra.json: the domain, built-in groups and endpoints
	// apps built on infrapi/lib and infrapi-cli discover instead of
	// configuring them.
	discovery.Register(engine, discovery.New(baseURL, apiDomain, discovery.Groups{
		System: catalog.SystemAPI, Catalog: catalog.CatalogAPI, Authorization: rbac.AuthorizationAPI,
	}, "/oauth2/userinfo", "/oauth2/discovery/keys", "/apis"))

	// Empty cfg.Sysadmin.Groups falls back to the single
	// "$platform-core-sysadmin" group the spec names — a deployment that
	// configures its own real groups there is never limited to it.
	sysadminGroups := cfg.Sysadmin.Groups
	if len(sysadminGroups) == 0 {
		sysadminGroups = []string{middleware.SysadminGroupFor(appCfg.AppPlatform)}
	}
	rbacRepo := rbac.NewRepository(s, keys)
	catalogRepo := catalog.NewRepository(s, keys)
	catalogRepo.TrustedIssuer = func(iss string) bool {
		_, ok := cfg.Federation.Issuer(iss)
		return ok
	}
	// Kayra's authorization server: tokens of its own, for infrapi-cli and
	// MCP clients, renewed and revoked
	saTokens := rbac.ServiceAccountTokens{TrustedIssuer: func(iss string) bool {
		_, ok := cfg.Federation.Issuer(iss)
		return ok
	}}
	if saTokens.DefaultTTL, saTokens.MaxTTL, err = serviceAccountTTLs(cfg); err != nil {
		return nil, err
	}
	if cfg.OAuth2.Enabled {
		as, err := oauth2server.New(cfg, authenticator, s, keys, baseURL)
		if err != nil {
			return nil, err
		}
		saTokens.Issuer = as
		// client_credentials: a service account, its keys and its
		// federated credentials
		as.Clients = func(clientID string) (oauth2server.MachineClient, error) {
			if api, ok := identity.ParseAPI(clientID); ok {
				uid, keys, federated, err := catalogRepo.ApiClient(appCfg.AppPlatform, appCfg.AppRegion, api)
				if errors.Is(err, store.ErrNotFound) {
					return oauth2server.MachineClient{}, oauth2server.ErrNoClient
				}
				return oauth2server.MachineClient{UID: uid, Kind: identity.KindAPI, Keys: keys, Federated: federated}, err
			}
			sa, err := rbacRepo.ServiceAccountClient(clientID)
			if errors.Is(err, store.ErrNotFound) {
				return oauth2server.MachineClient{}, oauth2server.ErrNoClient
			}
			if err != nil {
				return oauth2server.MachineClient{}, err
			}
			client := oauth2server.MachineClient{UID: sa.UID, Kind: identity.KindServiceAccount, Federated: sa.FederatedCredentials}
			if sa.JWKS != nil {
				client.Keys = sa.JWKS.Keys
			}
			return client, nil
		}
		// another user's sessions: the cluster RBAC's, the sysadmin first
		as.CanManageSessions = func(ac *middleware.AuthContext, verb string) bool {
			ok, _, err := rbacRepo.AuthorizeCluster(ac.UserID, ac.Groups, rbac.AuthorizationAPI, "sessions", verb)
			return ok && err == nil
		}
		as.RegisterRoutes(engine)
	}
	rbacRepo.SetSysadmin(sysadminGroups)
	// a token of one of Kayra's own identities: signed by the authorization
	// server's signer, never another provider's, and resolved from the
	// store, the service account still there with the token's uid, in a
	// namespace that still exists
	signer := cmp.Or(cfg.OAuth2.Signer, "self")
	authenticator.Machine = func(v *authn.Verified) (*middleware.AuthContext, error) {
		if v.Provider != signer {
			return nil, fmt.Errorf("apiserver: a token of one of Kayra's own identities, not signed by %s", signer)
		}
		sub, _ := v.Claims.GetSubject()
		uid, _ := v.Claims["uid"].(string)
		var ac *middleware.AuthContext
		switch kind, _ := v.Claims["kind"].(string); kind {
		case identity.KindServiceAccount:
			var err error
			if ac, err = rbacRepo.ServiceAccountContext(sub, uid); err != nil {
				return nil, err
			}
			if ns, _, _ := identity.ParseServiceAccount(sub); catalogRepo.CheckNamespace(ns) != nil {
				return nil, fmt.Errorf("apiserver: namespace %q of %s does not exist", ns, sub)
			}
		case identity.KindAPI:
			// the API still registered, the same registration
			api, ok := identity.ParseAPI(sub)
			if !ok {
				return nil, fmt.Errorf("apiserver: %q is no API's subject", sub)
			}
			reg, err := catalogRepo.GetClusterApiRegistration(appCfg.AppPlatform, appCfg.AppRegion, api)
			if err != nil || reg.UID == "" || reg.UID != uid || reg.Identity == nil {
				return nil, fmt.Errorf("apiserver: %s is no longer registered here, or no longer with an identity", sub)
			}
			ac = &middleware.AuthContext{UserID: sub, Groups: []string{identity.APIsGroup}, Kind: identity.KindAPI}
		default:
			return nil, fmt.Errorf("apiserver: unknown token kind %q", kind)
		}
		ac.Provider = v.Provider
		ac.Audience, _ = v.Claims.GetAudience()
		ac.ClientID = sub
		return ac, nil
	}

	userinfoHandler := func(c *gin.Context) {
		ac, ok := middleware.GetAuth(c)
		if !ok {
			httpapi.Fail(c, liberrors.New(http.StatusUnauthorized, "apiserver.Userinfo", "no authenticated caller on this request").
				WithSolution("send a bearer token: run `infrapi-cli login`"))
			return
		}
		body := gin.H{
			"sub":           ac.UserID,
			"provider":      ac.Provider,
			"authorization": ac.Authorization,
			"groups":        ac.Groups,
			"kind":          ac.Kind,
		}
		for k, v := range ac.Attributes {
			body[k] = v
		}
		// a token of the authorization server: what it was issued for, and
		// to whom, for an app to check it is its own (infrapi/lib)
		if ac.ClientID != "" {
			body["aud"], body["client_id"] = ac.Audience, ac.ClientID
		}
		c.JSON(http.StatusOK, body)
	}
	// The UserInfo Endpoint MUST support GET and MAY support POST (OIDC
	// Core §5.3.1) — most real providers accept both, so this does too.
	engine.GET("/oauth2/userinfo", authenticator.Middleware(), userinfoHandler)
	engine.POST("/oauth2/userinfo", authenticator.Middleware(), userinfoHandler)

	// Kayra's own cluster-scoped resources (namespaces, apiregistrations,
	// the cluster RBAC): authenticated, then decided on the cluster RBAC,
	// the built-in sysadmin binding first, as /check decides any app's
	// cluster-scoped resource
	cluster := engine.Group("", authenticator.Middleware(), rbac.RequireCluster(rbacRepo))
	pass := func(c *gin.Context) { c.Next() }
	rbac.RegisterClusterRoutes(cluster, rbacRepo, pass, func(rules []rbac.Rule) *liberrors.Error {
		return catalogRepo.ValidateClusterRoleRules(rules, appCfg.AppPlatform, appCfg.AppRegion)
	})
	rbac.RegisterNamespaceRoutes(engine, rbacRepo, authenticator.Middleware(), func(rules []rbac.Rule) *liberrors.Error {
		return catalogRepo.ValidateRoleRules(rules, appCfg.AppPlatform, appCfg.AppRegion)
	})
	rbac.RegisterServiceAccountRoutes(engine, rbacRepo, authenticator.Middleware(), saTokens)
	// catalog.Reconciler (the namespace/subscription/api registration
	// reconcile controller) deliberately does not run here: it's its own
	// "kayra reconciler" CLI command/process (see cmd/kayra), not a
	// goroutine mixed into the API server — easier to debug and scale
	// independently, and a crash in one never takes down the other.
	// /check's catalog-owned steps (see rbac.RegisterAuthorizeRoute for
	// the full order): the namespace exists, then — once the caller is
	// known to be a member — the api is registered here, the namespace is
	// subscribed to it, and that subscription is active.
	rbac.RegisterAuthorizeRoute(engine, rbacRepo, authenticator.Middleware(), rbac.Prechecks{
		Namespace: catalogRepo.CheckNamespace,
		Api: func(namespace, api string) *liberrors.Error {
			return catalogRepo.CheckApiSubscription(namespace, api, appCfg.AppPlatform, appCfg.AppRegion)
		},
		Resource: func(api, resource, verb string) *liberrors.Error {
			return catalogRepo.CheckApiResource(api, resource, verb, appCfg.AppPlatform, appCfg.AppRegion)
		},
		ClusterResource: func(api, resource, verb string) *liberrors.Error {
			return catalogRepo.CheckApiClusterResource(api, resource, verb, appCfg.AppPlatform, appCfg.AppRegion)
		},
		Builtin: func(api string) bool {
			return api == catalog.SystemAPI || api == catalog.CatalogAPI || api == rbac.AuthorizationAPI
		},
		MembersRead: func(api, resource, verb string) bool {
			return api == catalog.SystemAPI && resource == "namespaces" && (verb == "list" || verb == "get")
		},
	}, o.auditor)
	catalog.RegisterApiRegistrationRoutes(cluster, catalogRepo, pass, appCfg.AppPlatform, appCfg.AppRegion)
	catalog.RegisterNamespaceRoutes(engine, catalogRepo, rbacRepo, authenticator.Middleware(), appCfg.AppPlatform, appCfg.AppRegion)
	// reading the namespaces: whoever the cluster RBAC grants it sees every
	// one, anyone else the ones they are in, whatever their roles there
	catalog.RegisterNamespaceCollectionRoutes(cluster, engine.Group("", authenticator.Middleware()), catalogRepo,
		func(c *gin.Context, verb string) (bool, func(string) (bool, error), error) {
			ac, _ := middleware.GetAuth(c)
			if ac == nil {
				ac = &middleware.AuthContext{}
			}
			all, _, err := rbacRepo.AuthorizeCluster(ac.UserID, ac.Groups, catalog.SystemAPI, "namespaces", verb)
			if all || err != nil {
				return all, nil, err
			}
			if verb == "get" {
				return false, func(ns string) (bool, error) { return rbacRepo.IsNamespaceMember(ns, ac.UserID, ac.Groups) }, nil
			}
			members, err := rbacRepo.MemberNamespaces(ac.UserID, ac.Groups)
			return false, func(ns string) (bool, error) { return members[ns], nil }, err
		})
	// Discovery (GET /apis) and each registration's stored openapi spec:
	// any authenticated caller. Kayra's own groups are read from the
	// live route table, so they always match what this server serves.
	catalog.RegisterDiscoveryRoutes(engine, catalogRepo, authenticator.Middleware(), func() []catalog.Route {
		infos := engine.Routes()
		routes := make([]catalog.Route, len(infos))
		for i, ri := range infos {
			routes[i] = catalog.Route{Method: ri.Method, Path: ri.Path}
		}
		return routes
	}, appCfg.AppPlatform, appCfg.AppRegion)

	patTTLs, err := cfg.Tokens.Pat.Durations()
	if err != nil {
		return nil, err
	}
	// a user's personal access tokens; another user's: the cluster RBAC's,
	// the sysadmin first
	tokenapi.RegisterRoutes(engine, authenticator.Middleware(), tokenapi.Options{
		Root: "/apis/" + rbac.AuthorizationAPI + "/v1", Store: s, Keys: keys, Pub: &patKey.PublicKey, Config: cfg, TTLs: patTTLs,
		CanManageOthers: func(ac *middleware.AuthContext, verb string) bool {
			ok, _, err := rbacRepo.AuthorizeCluster(ac.UserID, ac.Groups, rbac.AuthorizationAPI, "tokens", verb)
			return ok && err == nil
		},
	})

	return engine, nil
}

// Roots are the roots of Kayra's own groups, system first: the primary
// root, whose metrics and specification also hold the routes under no
// group (/oauth2/*, /apis, /.well-known/kayra.json). Valid once the API
// domain is set (Build).
func Roots() []string {
	return []string{
		"/apis/" + catalog.SystemAPI + "/v1",
		"/apis/" + catalog.CatalogAPI + "/v1",
		"/apis/" + rbac.AuthorizationAPI + "/v1",
	}
}

// serviceAccountTTLs are a service account token's default and longest
// lifetimes, from serviceaccounts:.
func serviceAccountTTLs(cfg *gconfig.Config) (time.Duration, time.Duration, error) {
	d, err := cfg.ServiceAccounts.Durations()
	return d.Default, d.Max, err
}
