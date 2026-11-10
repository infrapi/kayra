// Package apiserver wires every other internal package onto the gin
// engine infrapi/lib's pkg/server builds, so main only has to call
// Build once.
package apiserver

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/authz"
	"github.com/infrapi/kayra/internal/catalog"
	gconfig "github.com/infrapi/kayra/internal/config"
	gcrypto "github.com/infrapi/kayra/internal/crypto"
	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/middleware"
	"github.com/infrapi/kayra/internal/oauth2broker"
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
func Build(appCfg *libconfig.AppConfig, cfg *gconfig.Config) (*gin.Engine, error) {
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

	engine, err := libserver.NewServerGin(appCfg)
	if err != nil {
		return nil, fmt.Errorf("apiserver: build gin engine: %w", err)
	}

	baseURL := appCfg.AppUrl

	// Empty cfg.App.APIDomain falls back to "example.com" — every API
	// group internal/rbac and internal/catalog mount, and every
	// Role.Rules entry an operator authors, is "<group>.<domain>", so
	// this must be resolved before either package registers a single
	// route, and before oauth2broker (which relays it to `kayra-cli
	// login` so the CLI never has to guess it either).
	apiDomain := cfg.App.APIDomain
	if apiDomain == "" {
		apiDomain = "example.com"
	}
	rbac.SetAPIDomain(apiDomain)
	catalog.SetAPIDomain(apiDomain)

	// Unknown paths get the same problem+json body as every other error
	// instead of gin's plain-text "404 page not found".
	engine.NoRoute(func(c *gin.Context) {
		httpapi.Fail(c, liberrors.New(http.StatusNotFound, "apiserver.NoRoute", "no route for %s %s", c.Request.Method, c.Request.URL.Path))
	})

	oidc.RegisterRoutes(engine, manager, baseURL)
	oauth2broker.RegisterRoutes(engine, cfg, s, keys, baseURL, apiDomain)

	userinfoHandler := func(c *gin.Context) {
		ac, ok := middleware.GetAuth(c)
		if !ok {
			httpapi.Fail(c, liberrors.New(http.StatusUnauthorized, "apiserver.Userinfo", "no authenticated caller on this request").
				WithSolution("send a bearer token: run `kayra-cli login`"))
			return
		}
		body := gin.H{
			"sub":           ac.UserID,
			"provider":      ac.Provider,
			"authorization": ac.Authorization,
			"groups":        ac.Groups,
		}
		for k, v := range ac.Attributes {
			body[k] = v
		}
		c.JSON(http.StatusOK, body)
	}
	// The UserInfo Endpoint MUST support GET and MAY support POST (OIDC
	// Core §5.3.1) — most real providers accept both, so this does too.
	engine.GET("/oauth2/userinfo", authenticator.Middleware(), userinfoHandler)
	engine.POST("/oauth2/userinfo", authenticator.Middleware(), userinfoHandler)

	// Empty cfg.Sysadmin.Groups falls back to the single
	// "$platform-core-sysadmin" group the spec names — a deployment that
	// configures its own real groups there is never limited to it.
	sysadminGroups := cfg.Sysadmin.Groups
	if len(sysadminGroups) == 0 {
		sysadminGroups = []string{middleware.SysadminGroupFor(appCfg.AppPlatform)}
	}
	sysadminGate := middleware.SysadminGate(authenticator, sysadminGroups)

	rbacRepo := rbac.NewRepository(s, keys)
	rbac.RegisterClusterRoutes(engine, rbacRepo, sysadminGate)
	rbac.RegisterNamespaceRoutes(engine, rbacRepo, authenticator.Middleware())
	// catalog.Reconciler (the namespace/subscription/api registration
	// reconcile controller) deliberately does not run here: it's its own
	// "kayra reconciler" CLI command/process (see cmd/kayra), not a
	// goroutine mixed into the API server — easier to debug and scale
	// independently, and a crash in one never takes down the other.
	catalogRepo := catalog.NewRepository(s, keys)
	// /check's catalog-owned steps (see rbac.RegisterAuthorizeRoute for
	// the full order): the namespace exists, then — once the caller is
	// known to be a member — the api is registered here, the namespace is
	// subscribed to it, and that subscription is active.
	rbac.RegisterAuthorizeRoute(engine, rbacRepo, authenticator.Middleware(), rbac.Prechecks{
		Namespace: catalogRepo.CheckNamespace,
		Api: func(namespace, api string) *liberrors.Error {
			return catalogRepo.CheckApiSubscription(namespace, api, appCfg.AppPlatform, appCfg.AppRegion)
		},
	})
	catalog.RegisterApiRegistrationRoutes(engine, catalogRepo, sysadminGate, appCfg.AppPlatform, appCfg.AppRegion)
	catalog.RegisterNamespaceRoutes(engine, catalogRepo, rbacRepo, authenticator.Middleware(), appCfg.AppPlatform, appCfg.AppRegion)
	catalog.RegisterNamespaceCollectionRoutes(engine, catalogRepo, sysadminGate)

	tokenapi.RegisterRoutes(engine, authenticator.Middleware(), s, keys, &patKey.PublicKey, cfg)

	return engine, nil
}
