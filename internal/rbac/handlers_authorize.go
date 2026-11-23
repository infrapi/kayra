package rbac

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/middleware"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// AuthorizeRequest is the body infrapi/lib's pkg/auth client sends to
// decide one request shaped "/apis/:api/v1/namespaces/:namespace/
// <resource>": Namespace/Api come from the URL, Resource/Verb from the
// rest of the path and the HTTP method — both parsed client-side, since
// the parsing rule itself (verbs match HTTP methods, everything past
// :api is Resource, an action is just part of Resource) needs no
// Kayra-specific knowledge to apply. Api is the calling app's own full
// API group URN (e.g. "compute.infrapi.io"), matching how it's
// actually reachable — never the bare app name.
//
// Namespace is "" for a cluster-scoped resource: decided on the cluster
// RBAC (Repository.AuthorizeCluster), never a namespace's.
type AuthorizeRequest struct {
	Namespace string `json:"namespace"`
	Api       string `json:"api" binding:"required"`
	Resource  string `json:"resource" binding:"required"`
	Verb      string `json:"verb" binding:"required"`
	// Name is the object the request names, when it names one: what an
	// API's implicit rules about itself read (ImplicitAPI).
	Name string `json:"name,omitempty"`
}

// AuthorizeResponse is this route's answer: Allowed decides it, Reason
// (set only when Allowed is false) is Authorize's own denial reason,
// surfaced back to the calling app's logs/response rather than re-derived.
type AuthorizeResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// Prechecks are the catalog-owned steps of a /check decision, passed in
// as functions because the dependency runs catalog -> rbac, never the
// other way (in practice catalog.Repository.CheckNamespace and
// CheckApiSubscription — see apiserver.Build). A nil field skips that
// step. A non-nil error aborts the check and is returned as-is.
type Prechecks struct {
	// Namespace is step 1: the namespace exists.
	Namespace func(namespace string) *liberrors.Error
	// Api is steps 3–5, run only for a member of the namespace: the api
	// is registered, the namespace is subscribed to it, and that
	// subscription is active.
	Api func(namespace, api string) *liberrors.Error
	// Resource is steps 6–7: the api's OpenAPI spec serves resource
	// (404), and verb on it (405).
	Resource func(api, resource, verb string) *liberrors.Error
	// ClusterResource is a cluster-scoped request's steps: the api is
	// registered, its spec serves resource cluster-scoped (404), and verb
	// on it (405).
	ClusterResource func(api, resource, verb string) *liberrors.Error
	// Builtin tells Kayra's own apis (system, catalog, authorization):
	// their resources are its routes', not a spec's, and in a namespace
	// they are decided as their routes are (CanManageNamespaceRBAC).
	Builtin func(api string) bool
	// MembersRead tells a cluster-scoped resource whose route lets anyone
	// read the namespaces they are in (system's namespaces, get and list):
	// listing is allowed, filtered; getting when they are in one.
	MembersRead func(api, resource, verb string) bool
}

// RegisterAuthorizeRoute mounts the one route other apps built on
// infrapi/lib call to authorize a request against this namespace's own
// RBAC objects: POST /apis/authorization.infrapi.io/v1/check, gated by
// gate (normally middleware.Authenticator, any configured provider) so
// the caller's user id and groups come from this same request's own
// resolved identity, not from the request body.
//
// "check" sits in the same api group ("authorization.infrapi.io")
// as the groups/roles/rolebindings it decides against, but is not
// itself gated by Allows against that group — exactly like
// Kubernetes' SelfSubjectAccessReview (authorization.k8s.io) needs no
// RBAC grant of its own: a caller can always ask "can I do X", since
// the answer never reveals more than the caller's own already-resolved
// identity already could.
//
// A cluster-scoped request (Namespace "") is decided on the cluster RBAC
// alone: the api registered and its spec serving resource cluster-scoped
// (prechecks.ClusterResource), then AuthorizeCluster, the built-in
// sysadmin binding and the global cluster role bindings. Kayra's own apis
// in a namespace are decided as their routes are, CanManageNamespaceRBAC.
// Any other request, an app's in a namespace, goes through these steps.
//
// Each step runs in this order and the first failure is the answer, so
// the reason a caller gets is the one that actually blocks them:
//
//  1. the namespace exists (prechecks.Namespace: 404),
//  2. the caller is a member of it (NamespaceMembership: denied),
//  3. the api is registered (prechecks.Api: 404),
//  4. the namespace is subscribed to it (prechecks.Api: 403),
//  5. that subscription is active (prechecks.Api: 403),
//  6. the api serves resource, per its OpenAPI spec
//     (prechecks.Resource: 404),
//  7. and supports verb on it (prechecks.Resource: 405),
//  8. a role bound to the caller's groups grants the api
//     (AuthorizeMember: denied),
//  9. that role grants verb on resource (AuthorizeMember: denied).
//
// Membership comes before anything about the api, so a non-member
// learns nothing about what a namespace is subscribed to, and the spec
// comes before roles, so a resource the app doesn't have is reported
// as that, not as an RBAC denial. A precheck failure is an error
// response; an RBAC denial (2, 8, 9) is a 200 with allowed:false and
// the reason.
func RegisterAuthorizeRoute(r gin.IRouter, repo *Repository, gate gin.HandlerFunc, prechecks Prechecks) {
	r.POST("/apis/"+AuthorizationAPI+"/v1/check", gate, func(c *gin.Context) {
		const origin = "rbac.Authorize"
		ac, ok := middleware.GetAuth(c)
		if !ok {
			httpapi.Fail(c, liberrors.New(http.StatusUnauthorized, origin, "not authenticated"))
			return
		}

		var req AuthorizeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, origin, ""))
			return
		}
		// a scoped personal access token: what its scope allows, whatever
		// the roles of its user
		if !ac.Scope.Allows(req.Api, req.Verb) {
			c.JSON(http.StatusOK, AuthorizeResponse{Allowed: false, Reason: fmt.Sprintf("your token's scope does not grant %q on api %q", req.Verb, req.Api)})
			return
		}
		builtin := prechecks.Builtin != nil && prechecks.Builtin(req.Api)

		// a cluster-scoped resource: an API's implicit rules about itself,
		// then the cluster RBAC
		if req.Namespace == "" {
			if ImplicitAPI(ac.UserID, req.Api, req.Resource, req.Verb, req.Name) {
				c.JSON(http.StatusOK, AuthorizeResponse{Allowed: true})
				return
			}
			if !builtin && prechecks.ClusterResource != nil {
				if perr := prechecks.ClusterResource(req.Api, req.Resource, req.Verb); perr != nil {
					httpapi.Fail(c, perr)
					return
				}
			}
			allowed, reason, err := repo.AuthorizeCluster(ac.UserID, ac.Groups, req.Api, req.Resource, req.Verb)
			if err != nil {
				httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin+".AuthorizeCluster", ""))
				return
			}
			if !allowed && prechecks.MembersRead != nil && prechecks.MembersRead(req.Api, req.Resource, req.Verb) {
				members, err := repo.MemberNamespaces(ac.UserID, ac.Groups)
				if err != nil {
					httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin+".MemberNamespaces", ""))
					return
				}
				allowed = req.Verb == "list" || len(members) > 0
				reason = ""
				if !allowed {
					reason = "you are a member of no namespace: neither your user id nor any of your groups is listed in any namespace's groups"
				}
			}
			c.JSON(http.StatusOK, AuthorizeResponse{Allowed: allowed, Reason: reason})
			return
		}

		if prechecks.Namespace != nil {
			if perr := prechecks.Namespace(req.Namespace); perr != nil {
				httpapi.Fail(c, perr)
				return
			}
		}

		// Kayra's own apis in a namespace: as their routes decide them
		if builtin {
			allowed, reason, err := repo.CanManageNamespaceRBAC(ac.UserID, ac.Groups, req.Namespace, req.Api, req.Resource, req.Verb)
			if err != nil {
				httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin+".CanManageNamespaceRBAC", ""))
				return
			}
			c.JSON(http.StatusOK, AuthorizeResponse{Allowed: allowed, Reason: reason})
			return
		}

		memberGroups, reason, err := repo.NamespaceMembership(req.Namespace, ac.UserID, ac.Groups)
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin+".NamespaceMembership", ""))
			return
		}
		if reason != "" {
			c.JSON(http.StatusOK, AuthorizeResponse{Allowed: false, Reason: reason})
			return
		}

		if prechecks.Api != nil {
			if perr := prechecks.Api(req.Namespace, req.Api); perr != nil {
				httpapi.Fail(c, perr)
				return
			}
		}
		if prechecks.Resource != nil {
			if perr := prechecks.Resource(req.Api, req.Resource, req.Verb); perr != nil {
				httpapi.Fail(c, perr)
				return
			}
		}

		allowed, reason, err := repo.AuthorizeMember(req.Namespace, memberGroups, req.Api, req.Resource, req.Verb)
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin+".AuthorizeMember", ""))
			return
		}

		c.JSON(http.StatusOK, AuthorizeResponse{Allowed: allowed, Reason: reason})
	})
}
