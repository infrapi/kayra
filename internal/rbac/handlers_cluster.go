package rbac

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// validateClusterRoleBinding checks that rb's role and every group it
// references exist at the cluster scope and share rb's exact metadata —
// "works only if region, platform and namespace match obviously."
func validateClusterRoleBinding(repo *Repository, rb RoleBinding) *liberrors.Error {
	role, err := repo.GetClusterRole(rb.Role)
	if err != nil {
		return liberrors.Wrap(err, http.StatusNotFound, "rbac.ClusterRoleBinding", "role %q not found", rb.Role)
	}
	if role.Metadata != rb.Metadata {
		return liberrors.New(http.StatusConflict, "rbac.ClusterRoleBinding", "role %q metadata does not match binding metadata", rb.Role)
	}

	for _, groupName := range rb.Groups {
		g, err := repo.GetClusterGroup(groupName)
		if err != nil {
			return liberrors.Wrap(err, http.StatusNotFound, "rbac.ClusterRoleBinding", "group %q not found", groupName)
		}
		if g.Metadata != rb.Metadata {
			return liberrors.New(http.StatusConflict, "rbac.ClusterRoleBinding", "group %q metadata does not match binding metadata", groupName)
		}
	}

	return nil
}

// RegisterClusterRoutes mounts full CRUD for the cluster bootstrap
// resources at /apis/authorization.example.com/v1/{clustergroups,
// clusterroles,clusterrolebindings} — cluster-scoped siblings of this
// package's own namespace-scoped groups/roles/rolebindings, same API
// group, "cluster" folded into the resource name itself rather than a
// separate path segment (mirroring how real k8s RBAC names ClusterRole/
// ClusterRoleBinding) — behind gate (normally middleware.SysadminGate) —
// the spec's "we need to configure 'cluster' levels rights which can't
// use the mechanism we try to implement to auth." These routes carry no
// RequireClusterRBAC check of their own: gate alone decides access, since
// a cluster bootstrap resource can't depend on the cluster RBAC it itself
// defines. The infra catalog (ApiRegistration) is registered
// separately, by internal/catalog's own RegisterApiRegistrationRoutes.
func RegisterClusterRoutes(r gin.IRouter, repo *Repository, gate gin.HandlerFunc) {
	group := r.Group("/apis/"+AuthorizationAPI+"/v1", gate)

	// --- clustergroups ---

	group.POST("/clustergroups", func(c *gin.Context) {
		var g Group
		if err := c.ShouldBindJSON(&g); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "rbac.CreateClusterGroup", ""))
			return
		}
		if g.Name == "" {
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, "rbac.CreateClusterGroup", "name is required"))
			return
		}
		if err := repo.PutClusterGroup(g); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.CreateClusterGroup", ""))
			return
		}
		c.JSON(http.StatusCreated, g)
	})

	group.GET("/clustergroups", func(c *gin.Context) {
		groups, err := repo.ListClusterGroups()
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.ListClusterGroups", ""))
			return
		}
		c.JSON(http.StatusOK, groups)
	})

	group.GET("/clustergroups/:group", func(c *gin.Context) {
		g, err := repo.GetClusterGroup(c.Param("group"))
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "rbac.GetClusterGroup", "group %q not found", c.Param("group")))
			return
		}
		c.JSON(http.StatusOK, g)
	})

	group.PUT("/clustergroups/:group", func(c *gin.Context) {
		name := c.Param("group")
		if _, err := repo.GetClusterGroup(name); err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "rbac.UpdateClusterGroup", "group %q not found", name))
			return
		}

		var g Group
		if err := c.ShouldBindJSON(&g); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "rbac.UpdateClusterGroup", ""))
			return
		}
		g.Name = name

		if err := repo.PutClusterGroup(g); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.UpdateClusterGroup", ""))
			return
		}
		c.JSON(http.StatusOK, g)
	})

	group.DELETE("/clustergroups/:group", func(c *gin.Context) {
		name := c.Param("group")
		if _, err := repo.GetClusterGroup(name); err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "rbac.DeleteClusterGroup", "group %q not found", name))
			return
		}
		if err := repo.DeleteClusterGroup(name); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.DeleteClusterGroup", ""))
			return
		}
		c.Status(http.StatusNoContent)
	})

	// --- clusterroles ---

	group.POST("/clusterroles", func(c *gin.Context) {
		var role Role
		if err := c.ShouldBindJSON(&role); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "rbac.CreateClusterRole", ""))
			return
		}
		if role.Name == "" {
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, "rbac.CreateClusterRole", "name is required"))
			return
		}
		if err := repo.PutClusterRole(role); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.CreateClusterRole", ""))
			return
		}
		c.JSON(http.StatusCreated, role)
	})

	group.GET("/clusterroles", func(c *gin.Context) {
		roles, err := repo.ListClusterRoles()
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.ListClusterRoles", ""))
			return
		}
		c.JSON(http.StatusOK, roles)
	})

	group.GET("/clusterroles/:role", func(c *gin.Context) {
		role, err := repo.GetClusterRole(c.Param("role"))
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "rbac.GetClusterRole", "role %q not found", c.Param("role")))
			return
		}
		c.JSON(http.StatusOK, role)
	})

	group.PUT("/clusterroles/:role", func(c *gin.Context) {
		name := c.Param("role")
		if _, err := repo.GetClusterRole(name); err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "rbac.UpdateClusterRole", "role %q not found", name))
			return
		}

		var role Role
		if err := c.ShouldBindJSON(&role); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "rbac.UpdateClusterRole", ""))
			return
		}
		role.Name = name

		if err := repo.PutClusterRole(role); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.UpdateClusterRole", ""))
			return
		}
		c.JSON(http.StatusOK, role)
	})

	group.DELETE("/clusterroles/:role", func(c *gin.Context) {
		name := c.Param("role")
		if _, err := repo.GetClusterRole(name); err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "rbac.DeleteClusterRole", "role %q not found", name))
			return
		}
		if err := repo.DeleteClusterRole(name); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.DeleteClusterRole", ""))
			return
		}
		c.Status(http.StatusNoContent)
	})

	// --- clusterrolebindings ---

	group.POST("/clusterrolebindings", func(c *gin.Context) {
		var rb RoleBinding
		if err := c.ShouldBindJSON(&rb); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "rbac.CreateClusterRoleBinding", ""))
			return
		}
		if rb.Name == "" || rb.Role == "" {
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, "rbac.CreateClusterRoleBinding", "name and role are required"))
			return
		}
		if err := validateClusterRoleBinding(repo, rb); err != nil {
			httpapi.Fail(c, err)
			return
		}
		if err := repo.PutClusterRoleBinding(rb); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.CreateClusterRoleBinding", ""))
			return
		}
		c.JSON(http.StatusCreated, rb)
	})

	group.GET("/clusterrolebindings", func(c *gin.Context) {
		bindings, err := repo.ListClusterRoleBindings()
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.ListClusterRoleBindings", ""))
			return
		}
		c.JSON(http.StatusOK, bindings)
	})

	group.GET("/clusterrolebindings/:rolebinding", func(c *gin.Context) {
		rb, err := repo.GetClusterRoleBinding(c.Param("rolebinding"))
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "rbac.GetClusterRoleBinding", "rolebinding %q not found", c.Param("rolebinding")))
			return
		}
		c.JSON(http.StatusOK, rb)
	})

	group.PUT("/clusterrolebindings/:rolebinding", func(c *gin.Context) {
		name := c.Param("rolebinding")
		if _, err := repo.GetClusterRoleBinding(name); err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "rbac.UpdateClusterRoleBinding", "rolebinding %q not found", name))
			return
		}

		var rb RoleBinding
		if err := c.ShouldBindJSON(&rb); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "rbac.UpdateClusterRoleBinding", ""))
			return
		}
		rb.Name = name
		if rb.Role == "" {
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, "rbac.UpdateClusterRoleBinding", "role is required"))
			return
		}
		if err := validateClusterRoleBinding(repo, rb); err != nil {
			httpapi.Fail(c, err)
			return
		}

		if err := repo.PutClusterRoleBinding(rb); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.UpdateClusterRoleBinding", ""))
			return
		}
		c.JSON(http.StatusOK, rb)
	})

	group.DELETE("/clusterrolebindings/:rolebinding", func(c *gin.Context) {
		name := c.Param("rolebinding")
		if _, err := repo.GetClusterRoleBinding(name); err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "rbac.DeleteClusterRoleBinding", "rolebinding %q not found", name))
			return
		}
		if err := repo.DeleteClusterRoleBinding(name); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.DeleteClusterRoleBinding", ""))
			return
		}
		c.Status(http.StatusNoContent)
	})
}

// notFoundOrInternal turns a Repository Get error into a 404 when it is
// store.ErrNotFound, or a 500 for anything else (a corrupt record, a
// backend outage), always carrying origin/format/args as the detail.
func notFoundOrInternal(err error, origin, format string, args ...any) *liberrors.Error {
	if err == store.ErrNotFound {
		return liberrors.New(http.StatusNotFound, origin, format, args...)
	}
	return liberrors.Wrap(err, http.StatusInternalServerError, origin, format, args...)
}
