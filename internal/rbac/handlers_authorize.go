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

// RegisterAuthorizeRoute mounts the one route other apps built on
// infrapi/lib call to authorize a request against this namespace's own
// RBAC objects (see Repository.Authorize): POST
// /apis/authorization.example.com/v1/check, gated by gate (normally
// middleware.Authenticator, any configured provider) so the caller's
// user id and groups come from this same request's own resolved
// identity, not from the request body.
//
// "check" sits in the same api group ("authorization.example.com")
// as the groups/roles/rolebindings it decides against, but is not
// itself gated by Allows against that group — exactly like
// Kubernetes' SelfSubjectAccessReview (authorization.k8s.io) needs no
// RBAC grant of its own: a caller can always ask "can I do X", since
// the answer never reveals more than the caller's own already-resolved
// identity already could.
func RegisterAuthorizeRoute(r gin.IRouter, repo *Repository, gate gin.HandlerFunc) {
	r.POST("/apis/"+AuthorizationAPI+"/v1/check", gate, func(c *gin.Context) {
		ac, ok := middleware.GetAuth(c)
		if !ok {
			httpapi.Fail(c, liberrors.New(http.StatusUnauthorized, "rbac.Authorize", "not authenticated"))
			return
		}

		var req AuthorizeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "rbac.Authorize", ""))
			return
		}

		allowed, reason, err := repo.Authorize(ac.UserID, ac.Groups, req.Namespace, req.Api, req.Resource, req.Verb)
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.Authorize", ""))
			return
		}

		c.JSON(http.StatusOK, AuthorizeResponse{Allowed: allowed, Reason: reason})
	})
}
