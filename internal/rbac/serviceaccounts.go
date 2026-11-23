package rbac

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/identity"
	"github.com/infrapi/kayra/internal/middleware"
	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// validateGroupMembers refuses a group naming Kayra's own identities
// where they cannot be: a reserved user anywhere (a service account goes
// in ServiceAccounts), a reserved group other than its own namespace's
// service accounts' (a namespace group only), service accounts in a
// cluster group, a service account name that is no DNS label, and an API
// that is no API group.
func validateGroupMembers(g Group, cluster bool, origin string) *liberrors.Error {
	for _, u := range g.Users {
		if identity.IsReserved(u) {
			return liberrors.New(http.StatusBadRequest, origin, "users: %q: the %q prefix is Kayra's own", u, identity.Reserved).
				WithSolution("name a service account in serviceaccounts, in a group of its own namespace, an API in apis")
		}
	}
	for _, gr := range g.Groups {
		if !identity.IsReserved(gr) {
			continue
		}
		if cluster || gr != identity.NamespaceServiceAccounts(g.Metadata.Namespace) {
			return liberrors.New(http.StatusBadRequest, origin, "groups: %q: the only reserved group a group may name is its own namespace's service accounts', %q, in a namespace group",
				gr, identity.NamespaceServiceAccounts(g.Metadata.Namespace))
		}
	}
	if cluster && len(g.ServiceAccounts) > 0 {
		return liberrors.New(http.StatusBadRequest, origin, "serviceaccounts: a cluster group names none: a service account acts in its own namespace only").
			WithSolution("name it in a group of its namespace")
	}
	for _, name := range g.ServiceAccounts {
		if !identity.ValidName(name) {
			return liberrors.New(http.StatusBadRequest, origin, "serviceaccounts: %q: a service account of the group's namespace, by name (a DNS label)", name)
		}
	}
	for _, api := range g.APIs {
		if !identity.ValidAPIGroup(api) {
			return liberrors.New(http.StatusBadRequest, origin, "apis: %q: an API by its group, exactly, like compute.infrapi.io", api)
		}
	}
	return nil
}

// TokenIssuer signs a machine token: Kayra's authorization server
// (oauth2server.Server.IssueMachineToken). audience is its resources.
type TokenIssuer interface {
	// IssueMachineToken signs a token of subject, its uid and kind, for
	// audience, valid ttl.
	IssueMachineToken(subject, uid, kind string, audience []string, ttl time.Duration) (token string, expires time.Time, err error)
	// Resources are the audiences a token may be issued for, the first the
	// default.
	Resources() []string
	// AllowedResource tells whether a token may be issued for resource.
	AllowedResource(resource string) bool
}

// ServiceAccountTokens configures the token action: the issuer, nil when
// the authorization server is off (the action then answers 501), and the
// lifetimes.
type ServiceAccountTokens struct {
	Issuer     TokenIssuer
	DefaultTTL time.Duration
	MaxTTL     time.Duration
	// TrustedIssuer tells an issuer of federation.issuers: a federated
	// credential names one, or is refused. None is when nil.
	TrustedIssuer func(issuer string) bool
}

// validateServiceAccount refuses unsound keys and federated credentials
// (identity.CheckCredentials).
func validateServiceAccount(sa ServiceAccount, tokens ServiceAccountTokens, origin string) *liberrors.Error {
	err := identity.CheckCredentials(sa.JWKS, sa.FederatedCredentials, tokens.TrustedIssuer)
	if err == nil {
		return nil
	}
	e := liberrors.New(http.StatusBadRequest, origin, "%s", err)
	if errors.Is(err, identity.ErrUntrustedIssuer) {
		e = e.WithSolution("ask Kayra's admin to add it to federation.issuers")
	}
	return e
}

// ServiceAccountClient is a service account as a client of the token
// endpoint (client_credentials): its uid, its keys and its federated
// credentials. store.ErrNotFound when there is none.
func (r *Repository) ServiceAccountClient(subject string) (ServiceAccount, error) {
	namespace, name, ok := identity.ParseServiceAccount(subject)
	if !ok {
		return ServiceAccount{}, store.ErrNotFound
	}
	return r.GetNamespaceServiceAccount(namespace, name)
}

// tokenRequest is the body of the token action.
type tokenRequest struct {
	// ExpiresIn is the token's lifetime, a Go duration (1h): the
	// configured default when empty.
	ExpiresIn string `json:"expires_in"`
	// Audience are the resources the token is for: the authorization
	// server's first resource, Kayra, when empty.
	Audience []string `json:"audience"`
}

// tokenResponse is what the token action answers.
type tokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RegisterServiceAccountRoutes mounts a namespace's service accounts at
// /apis/authorization.infrapi.io/v1/namespaces/:namespace/serviceaccounts,
// behind gate then the same check as its other RBAC objects
// (RequireClusterRBAC): create, list, get, update (its description),
// delete, and the token action, POST .../serviceaccounts/:name/token,
// its own permission (serviceaccounts/token, create), whoever holds it
// acting with the service account's rights.
func RegisterServiceAccountRoutes(r gin.IRouter, repo *Repository, gate gin.HandlerFunc, tokens ServiceAccountTokens) {
	group := r.Group("/apis/"+AuthorizationAPI+"/v1/namespaces/:namespace", gate)
	const resource = "serviceaccounts"

	group.POST("/serviceaccounts", RequireClusterRBAC(repo, AuthorizationAPI, resource, "create"), func(c *gin.Context) {
		const origin = "rbac.CreateServiceAccount"
		namespace := c.Param("namespace")
		var sa ServiceAccount
		if err := c.ShouldBindJSON(&sa); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, origin, ""))
			return
		}
		if !identity.ValidName(sa.Name) {
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, origin, "name %q: a DNS label, lower case letters, digits and -", sa.Name))
			return
		}
		if err := resolveNamespace(&sa.Metadata, namespace); err != nil {
			httpapi.Fail(c, err)
			return
		}
		if _, err := repo.GetNamespaceServiceAccount(namespace, sa.Name); err == nil {
			httpapi.Fail(c, liberrors.New(http.StatusConflict, origin, "service account %q exists in namespace %q", sa.Name, namespace))
			return
		} else if !errors.Is(err, store.ErrNotFound) {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin, ""))
			return
		}
		if err := validateServiceAccount(sa, tokens, origin); err != nil {
			httpapi.Fail(c, err)
			return
		}
		sa.UID = rand.Text()
		if err := repo.PutNamespaceServiceAccount(namespace, &sa); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin, ""))
			return
		}
		c.JSON(http.StatusCreated, sa)
	})

	group.GET("/serviceaccounts", RequireClusterRBAC(repo, AuthorizationAPI, resource, "list"), func(c *gin.Context) {
		sas, err := repo.ListNamespaceServiceAccounts(c.Param("namespace"))
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.ListServiceAccounts", ""))
			return
		}
		c.JSON(http.StatusOK, sas)
	})

	group.GET("/serviceaccounts/:serviceaccount", RequireClusterRBAC(repo, AuthorizationAPI, resource, "get"), func(c *gin.Context) {
		namespace, name := c.Param("namespace"), c.Param("serviceaccount")
		sa, err := repo.GetNamespaceServiceAccount(namespace, name)
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "rbac.GetServiceAccount", "service account %q not found", name))
			return
		}
		c.JSON(http.StatusOK, sa)
	})

	group.PUT("/serviceaccounts/:serviceaccount", RequireClusterRBAC(repo, AuthorizationAPI, resource, "update"), func(c *gin.Context) {
		const origin = "rbac.UpdateServiceAccount"
		namespace, name := c.Param("namespace"), c.Param("serviceaccount")
		old, err := repo.GetNamespaceServiceAccount(namespace, name)
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, origin, "service account %q not found", name))
			return
		}
		var sa ServiceAccount
		if err := c.ShouldBindJSON(&sa); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, origin, ""))
			return
		}
		if err := resolveNamespace(&sa.Metadata, namespace); err != nil {
			httpapi.Fail(c, err)
			return
		}
		// its identity is not the request's to change
		sa.Name, sa.UID, sa.CreatedAt = name, old.UID, old.CreatedAt
		if err := validateServiceAccount(sa, tokens, origin); err != nil {
			httpapi.Fail(c, err)
			return
		}
		if err := repo.PutNamespaceServiceAccount(namespace, &sa); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin, ""))
			return
		}
		c.JSON(http.StatusOK, sa)
	})

	group.DELETE("/serviceaccounts/:serviceaccount", RequireClusterRBAC(repo, AuthorizationAPI, resource, "delete"), func(c *gin.Context) {
		const origin = "rbac.DeleteServiceAccount"
		namespace, name := c.Param("namespace"), c.Param("serviceaccount")
		if _, err := repo.GetNamespaceServiceAccount(namespace, name); err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, origin, "service account %q not found", name))
			return
		}
		if err := repo.DeleteNamespaceServiceAccount(namespace, name); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin, ""))
			return
		}
		c.Status(http.StatusNoContent)
	})

	group.POST("/serviceaccounts/:serviceaccount/token", RequireClusterRBAC(repo, AuthorizationAPI, resource+"/token", "create"), func(c *gin.Context) {
		const origin = "rbac.ServiceAccountToken"
		namespace, name := c.Param("namespace"), c.Param("serviceaccount")
		if tokens.Issuer == nil {
			httpapi.Fail(c, liberrors.New(http.StatusNotImplemented, origin, "service account tokens need Kayra's authorization server").
				WithSolution("set oauth2.enabled in Kayra's configuration"))
			return
		}
		sa, err := repo.GetNamespaceServiceAccount(namespace, name)
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, origin, "service account %q not found", name))
			return
		}
		var req tokenRequest
		if c.Request.ContentLength != 0 {
			if err := c.ShouldBindJSON(&req); err != nil {
				httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, origin, ""))
				return
			}
		}
		ttl := tokens.DefaultTTL
		if req.ExpiresIn != "" {
			if ttl, err = time.ParseDuration(req.ExpiresIn); err != nil || ttl <= 0 {
				httpapi.Fail(c, liberrors.New(http.StatusBadRequest, origin, "expires_in %q: a duration, like 1h", req.ExpiresIn))
				return
			}
		}
		if ttl > tokens.MaxTTL {
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, origin, "expires_in %s: more than the %s a token may last", ttl, tokens.MaxTTL).
				WithSolution("ask for a new token when it expires; a CI gets one from its platform's identity"))
			return
		}
		audience := req.Audience
		if len(audience) == 0 {
			audience = tokens.Issuer.Resources()[:1]
		}
		for _, a := range audience {
			if !tokens.Issuer.AllowedResource(a) {
				httpapi.Fail(c, liberrors.New(http.StatusBadRequest, origin, "audience %q: not one of the resources tokens are issued for (%v)", a, tokens.Issuer.Resources()))
				return
			}
		}
		token, expires, err := tokens.Issuer.IssueMachineToken(identity.ServiceAccount(namespace, name), sa.UID, identity.KindServiceAccount, slices.Clone(audience), ttl)
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin, ""))
			return
		}
		c.JSON(http.StatusCreated, tokenResponse{Token: token, ExpiresAt: expires})
	})
}

// ServiceAccountContext resolves a service account's token, its claims
// already verified as signed by Kayra's authorization server: the service
// account must exist with the token's uid, so a token of a deleted one,
// even one recreated under the same name, is refused.
func (r *Repository) ServiceAccountContext(subject, uid string) (*middleware.AuthContext, error) {
	namespace, name, ok := identity.ParseServiceAccount(subject)
	if !ok {
		return nil, fmt.Errorf("rbac: %q is no service account", subject)
	}
	sa, err := r.GetNamespaceServiceAccount(namespace, name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("rbac: service account %s/%s does not exist", namespace, name)
	}
	if err != nil {
		return nil, err
	}
	if uid == "" || sa.UID != uid {
		return nil, fmt.Errorf("rbac: the token is of an earlier service account %s/%s", namespace, name)
	}
	return &middleware.AuthContext{
		UserID: subject,
		Kind:   identity.KindServiceAccount,
		Groups: identity.ServiceAccountGroups(namespace),
	}, nil
}
