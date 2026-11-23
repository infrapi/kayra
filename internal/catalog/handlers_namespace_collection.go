package catalog

import (
	"net/http"
	"slices"
	"strings"

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

// NamespaceVisibility is which namespaces a caller reading the
// collection sees: every one when all, else those member counts them in,
// whatever their roles there. verb is list or get.
type NamespaceVisibility func(c *gin.Context, verb string) (all bool, member func(namespace string) (bool, error), err error)

// RegisterNamespaceCollectionRoutes mounts the namespace resource itself
// — Kayra's unit of isolation, which a tenant owns one or several of.
// Creating, renaming or deleting one is a cluster-wide administrative
// action, same trust tier as an ApiRegistration: on writers, normally a
// group behind the authenticator and rbac.RequireCluster, the cluster
// RBAC. Reading is on readers, behind the authenticator only: whoever the
// cluster RBAC grants it sees every namespace, anyone else the ones they
// are in (visible; every one when nil).
func RegisterNamespaceCollectionRoutes(writers, readers gin.IRouter, repo *Repository, visible NamespaceVisibility) {
	path := "/apis/" + SystemAPI + "/v1/namespaces"
	group := writers.Group(path)
	read := readers.Group(path)
	if visible == nil {
		visible = func(*gin.Context, string) (bool, func(string) (bool, error), error) { return true, nil, nil }
	}

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

	read.GET("", func(c *gin.Context) {
		all, member, err := visible(c, "list")
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.ListNamespaces", ""))
			return
		}
		namespaces, err := repo.ListNamespaces()
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.ListNamespaces", ""))
			return
		}
		slices.SortFunc(namespaces, func(a, b Namespace) int { return strings.Compare(a.Name, b.Name) })
		out := make([]gin.H, 0, len(namespaces))
		for _, n := range namespaces {
			if !all {
				in, err := member(n.Name)
				if err != nil {
					httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.ListNamespaces", ""))
					return
				}
				if !in {
					continue
				}
			}
			out = append(out, namespaceResponse(n))
		}
		c.JSON(http.StatusOK, out)
	})

	read.GET("/:namespace", func(c *gin.Context) {
		name := c.Param("namespace")
		n, err := repo.GetNamespace(name)
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "catalog.GetNamespace", "namespace %q not found", name))
			return
		}
		all, member, err := visible(c, "get")
		if err == nil && !all {
			all, err = member(name)
			if err == nil && !all {
				httpapi.Fail(c, liberrors.New(http.StatusForbidden, "catalog.GetNamespace",
					"you are not a member of namespace %q: neither your user id nor any of your groups is listed in any of its groups", name).
					WithSolution("ask its admins to add you, or one of your groups, to one of its groups"))
				return
			}
		}
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.GetNamespace", ""))
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
