package catalog

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/httpapi"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// namespaceUpsertRequest is the request body for creating a namespace.
// Name is only read on create (POST to the collection, which has no
// :namespace path param); on update the path segment is always
// authoritative. Active is deliberately absent: it's a computed field,
// never settable by the client — a namespace is always created
// disabled, and can only ever be flipped active by
// Repository.ActivateNamespace (an internal-only path no HTTP route
// exposes).
type namespaceUpsertRequest struct {
	Name string `json:"name"`
}

// namespaceResponse is what every namespace handler returns.
func namespaceResponse(n Namespace) gin.H {
	return gin.H{"name": n.Name, "active": n.Active, "created_at": n.CreatedAt, "updated_at": n.UpdatedAt}
}

// RegisterNamespaceCollectionRoutes mounts the namespace resource itself
// — the legacy model's "Tenant": a namespace and a tenant
// are the same thing, so there is no separate /tenant child resource —
// on r, gated by gate (normally middleware.SysadminGate). Creating,
// renaming or deleting a namespace is a cluster-wide administrative
// action, same trust tier as an ApiRegistration, not something that can be
// bootstrapped via per-namespace RBAC (there is nothing to check RBAC
// against before the namespace exists) — unlike Subscription, this
// package's namespace-collection routes have no dependency on
// internal/rbac at all.
func RegisterNamespaceCollectionRoutes(r gin.IRouter, repo *Repository, gate gin.HandlerFunc) {
	group := r.Group("/apis/"+SystemAPI+"/v1/namespaces", gate)

	group.POST("", func(c *gin.Context) {
		var req namespaceUpsertRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "catalog.CreateNamespace", ""))
			return
		}
		if req.Name == "" {
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, "catalog.CreateNamespace", "name is required"))
			return
		}

		n := Namespace{Name: req.Name, Active: false}
		if err := repo.PutNamespace(&n); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.CreateNamespace", ""))
			return
		}
		c.JSON(http.StatusCreated, namespaceResponse(n))
	})

	group.GET("", func(c *gin.Context) {
		namespaces, err := repo.ListNamespaces()
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.ListNamespaces", ""))
			return
		}
		out := make([]gin.H, len(namespaces))
		for i, n := range namespaces {
			out[i] = namespaceResponse(n)
		}
		c.JSON(http.StatusOK, out)
	})

	group.GET("/:namespace", func(c *gin.Context) {
		n, err := repo.GetNamespace(c.Param("namespace"))
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "catalog.GetNamespace", "namespace %q not found", c.Param("namespace")))
			return
		}
		c.JSON(http.StatusOK, namespaceResponse(n))
	})

	// PUT is a no-op confirmation, kept for API shape compatibility: the
	// path segment is the only thing that ever identified a namespace,
	// and name/active are both fixed/computed — there is nothing left in
	// the body a caller could legitimately change.
	group.PUT("/:namespace", func(c *gin.Context) {
		name := c.Param("namespace")
		n, err := repo.GetNamespace(name)
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "catalog.UpdateNamespace", "namespace %q not found", name))
			return
		}
		c.JSON(http.StatusOK, namespaceResponse(n))
	})

	group.DELETE("/:namespace", func(c *gin.Context) {
		name := c.Param("namespace")
		if _, err := repo.GetNamespace(name); err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "catalog.DeleteNamespace", "namespace %q not found", name))
			return
		}
		if err := repo.DeleteNamespace(name); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.DeleteNamespace", ""))
			return
		}
		c.Status(http.StatusNoContent)
	})
}
