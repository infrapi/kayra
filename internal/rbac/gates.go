package rbac

import (
	"context"
	"net/http"

	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/middleware"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// Caller is the request's authenticated caller, from its context; a 401
// without one.
func Caller(ctx context.Context, origin string) (*middleware.AuthContext, error) {
	ac, ok := middleware.AuthOf(ctx)
	if !ok {
		return nil, liberrors.New(http.StatusUnauthorized, origin, "not authenticated")
	}
	return ac, nil
}

// AuthorizeClusterRequest decides a cluster-scoped request on the cluster
// RBAC, its api, resource and verb read from its path and method as /check
// reads them (ClusterRequest), an API's implicit rules about itself first:
// for a handler of the generated Handlers.
func (r *Repository) AuthorizeClusterRequest(ctx context.Context) error {
	const origin = "rbac.RequireCluster"
	ac, err := Caller(ctx, origin)
	if err != nil {
		return err
	}
	req := httpapi.RequestOf(ctx)
	api, resource, verb, perr := ClusterRequest(req.Path, req.Method)
	if perr != nil {
		return liberrors.Wrap(perr, http.StatusNotFound, origin, "")
	}
	if ImplicitAPI(ac.UserID, api, resource, verb, req.Params.ByName("name")) {
		return nil
	}
	allowed, reason, aerr := r.AuthorizeCluster(ac.UserID, ac.Groups, api, resource, verb)
	if aerr != nil {
		return liberrors.Wrap(aerr, http.StatusInternalServerError, origin, "")
	}
	if !allowed {
		return liberrors.New(http.StatusForbidden, origin, "not authorized to %s %s of api %q: %s", verb, resource, api, reason)
	}
	return nil
}

// AuthorizeNamespaceRBAC decides managing api's resource in namespace:
// CanManageNamespaceRBAC, for a handler of the generated Handlers.
func (r *Repository) AuthorizeNamespaceRBAC(ctx context.Context, namespace, api, resource, verb string) error {
	const origin = "rbac.RequireClusterRBAC"
	ac, err := Caller(ctx, origin)
	if err != nil {
		return err
	}
	allowed, reason, aerr := r.CanManageNamespaceRBAC(ac.UserID, ac.Groups, namespace, api, resource, verb)
	if aerr != nil {
		return liberrors.Wrap(aerr, http.StatusInternalServerError, origin, "")
	}
	if !allowed {
		return liberrors.New(http.StatusForbidden, origin, "not authorized to %s rbac %s in namespace %q: %s", verb, resource, namespace, reason)
	}
	return nil
}
