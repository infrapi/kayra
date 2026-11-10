package rbac

import (
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
// API group URN (e.g. "compute.example.com"), matching how it's
// actually reachable — never the bare app name.
type AuthorizeRequest struct {
	Namespace string `json:"namespace" binding:"required"`
	Api       string `json:"api" binding:"required"`
	Resource  string `json:"resource" binding:"required"`
	Verb      string `json:"verb" binding:"required"`
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
}

// RegisterAuthorizeRoute mounts the one route other apps built on
// infrapi/lib call to authorize a request against this namespace's own
// RBAC objects: POST /apis/authorization.example.com/v1/check, gated by
// gate (normally middleware.Authenticator, any configured provider) so
// the caller's user id and groups come from this same request's own
// resolved identity, not from the request body.
//
// "check" sits in the same api group ("authorization.example.com")
// as the groups/roles/rolebindings it decides against, but is not
// itself gated by Allows against that group — exactly like
// Kubernetes' SelfSubjectAccessReview (authorization.k8s.io) needs no
// RBAC grant of its own: a caller can always ask "can I do X", since
// the answer never reveals more than the caller's own already-resolved
// identity already could.
//
// Each step runs in this order and the first failure is the answer, so
// the reason a caller gets is the one that actually blocks them:
//
//  1. the namespace exists (prechecks.Namespace: 404),
//  2. the caller is a member of it (NamespaceMembership: denied),
//  3. the api is registered (prechecks.Api: 404),
//  4. the namespace is subscribed to it (prechecks.Api: 403),
//  5. that subscription is active (prechecks.Api: 403),
//  6. a role bound to the caller's groups grants the api
//     (AuthorizeMember: denied),
//  7. that role grants verb on resource (AuthorizeMember: denied).
//
// Membership comes before anything about the api, so a non-member
// learns nothing about what a namespace is subscribed to. A precheck
// failure is an error response; an RBAC denial (2, 6, 7) is a 200 with
// allowed:false and the reason.
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

		if prechecks.Namespace != nil {
			if perr := prechecks.Namespace(req.Namespace); perr != nil {
				httpapi.Fail(c, perr)
				return
			}
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

		allowed, reason, err := repo.AuthorizeMember(req.Namespace, memberGroups, req.Api, req.Resource, req.Verb)
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin+".AuthorizeMember", ""))
			return
		}

		c.JSON(http.StatusOK, AuthorizeResponse{Allowed: allowed, Reason: reason})
	})
}
