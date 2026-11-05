package rbac

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/middleware"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// resolveNamespace applies the spec's "if empty equal to :namespace, any
// other value are rejected" rule to a resource's metadata.namespace.
func resolveNamespace(m *Metadata, pathNamespace string) *liberrors.Error {
	if m.Namespace == "" {
		m.Namespace = pathNamespace
		return nil
	}
	if m.Namespace != pathNamespace {
		return liberrors.New(http.StatusBadRequest, "rbac.resolveNamespace",
			"metadata.namespace %q does not match path namespace %q", m.Namespace, pathNamespace)
	}
	return nil
}

// validateNamespaceRoleBinding checks that rb's role and every group it
// references exist in namespace and share rb's exact metadata — "works
// only if region, platform and namespace match obviously."
func validateNamespaceRoleBinding(repo *Repository, namespace string, rb RoleBinding) *liberrors.Error {
	role, err := repo.GetNamespaceRole(namespace, rb.Role)
	if err != nil {
		return notFoundOrInternal(err, "rbac.NamespaceRoleBinding", "role %q not found", rb.Role)
	}
	if role.Metadata != rb.Metadata {
		return liberrors.New(http.StatusConflict, "rbac.NamespaceRoleBinding", "role %q metadata does not match binding metadata", rb.Role)
	}

	for _, groupName := range rb.Groups {
		g, err := repo.GetNamespaceGroup(namespace, groupName)
		if err != nil {
			return notFoundOrInternal(err, "rbac.NamespaceRoleBinding", "group %q not found", groupName)
		}
		if g.Metadata != rb.Metadata {
			return liberrors.New(http.StatusConflict, "rbac.NamespaceRoleBinding", "group %q metadata does not match binding metadata", groupName)
		}
	}

	return nil
}

// RequireClusterRBAC gates one namespace route on repo.CanManageNamespaceRBAC:
// the caller's own user id or resolved groups (set by the preceding auth
// gate) must match a cluster Group bound to a cluster Role granting api +
// verb on resource, scoped to this request's :namespace. This is what
// closes the gap where any authenticated caller could manage RBAC
// objects in any namespace regardless of their actual cluster-level
// rights. api is AuthorizationAPI for this package's own groups/roles/
// rolebindings routes, SubscriptionAPI for internal/catalog's
// Subscription routes — see those constants in authorize.go.
func RequireClusterRBAC(repo *Repository, api, resource, verb string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ac, ok := middleware.GetAuth(c)
		if !ok {
			httpapi.Fail(c, liberrors.New(http.StatusUnauthorized, "rbac.RequireClusterRBAC", "not authenticated"))
			return
		}

		namespace := c.Param("namespace")
		allowed, reason, err := repo.CanManageNamespaceRBAC(ac.UserID, ac.Groups, namespace, api, resource, verb)
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.RequireClusterRBAC", ""))
			return
		}
		if !allowed {
			httpapi.Fail(c, liberrors.New(http.StatusForbidden, "rbac.RequireClusterRBAC",
				"not authorized to %s rbac %s in namespace %q: %s", verb, resource, namespace, reason))
			return
		}

		c.Next()
	}
}

// RegisterNamespaceRoutes mounts full CRUD for the per-namespace default
// groups/roles/rolebindings resources at
// /apis/authorization.example.com/v1/namespaces/:namespace/{groups,
// roles,rolebindings} — Kayra's own authorization management plane,
// its own API group exactly like any other app's own
// /apis/<app>.example.com/v1/namespaces/:namespace/<resource> routes —
// behind gate (normally middleware.Authenticator, any configured
// provider) followed by RequireClusterRBAC, so only a caller whose
// cluster-level group membership grants them AuthorizationAPI rights
// in this specific namespace — the spec's bootstrap flow — can act on
// it. RequireClusterRBAC is exported so internal/catalog can gate its
// own namespace-scoped Subscription routes through the exact same check,
// against SubscriptionAPI instead. The namespace resource itself
// (the legacy model's "Tenant") and the infra catalog
// (ApiRegistration/Subscription) are registered separately, by
// internal/catalog's own RegisterClusterRoutes/RegisterNamespaceRoutes/
// RegisterNamespaceCollectionRoutes.
func RegisterNamespaceRoutes(r gin.IRouter, repo *Repository, gate gin.HandlerFunc) {
	group := r.Group("/apis/"+AuthorizationAPI+"/v1/namespaces/:namespace", gate)

	// --- groups ---

	group.POST("/groups", RequireClusterRBAC(repo, AuthorizationAPI, "groups", "create"), func(c *gin.Context) {
		namespace := c.Param("namespace")

		var g Group
		if err := c.ShouldBindJSON(&g); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "rbac.CreateNamespaceGroup", ""))
			return
		}
		if g.Name == "" {
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, "rbac.CreateNamespaceGroup", "name is required"))
			return
		}
		if err := resolveNamespace(&g.Metadata, namespace); err != nil {
			httpapi.Fail(c, err)
			return
		}

		if err := repo.PutNamespaceGroup(namespace, g); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.CreateNamespaceGroup", ""))
			return
		}
		c.JSON(http.StatusCreated, g)
	})

	group.GET("/groups", RequireClusterRBAC(repo, AuthorizationAPI, "groups", "list"), func(c *gin.Context) {
		groups, err := repo.ListNamespaceGroups(c.Param("namespace"))
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.ListNamespaceGroups", ""))
			return
		}
		c.JSON(http.StatusOK, groups)
	})

	group.GET("/groups/:group", RequireClusterRBAC(repo, AuthorizationAPI, "groups", "get"), func(c *gin.Context) {
		namespace, name := c.Param("namespace"), c.Param("group")
		g, err := repo.GetNamespaceGroup(namespace, name)
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "rbac.GetNamespaceGroup", "group %q not found", name))
			return
		}
		c.JSON(http.StatusOK, g)
	})

	group.PUT("/groups/:group", RequireClusterRBAC(repo, AuthorizationAPI, "groups", "update"), func(c *gin.Context) {
		namespace, name := c.Param("namespace"), c.Param("group")
		if _, err := repo.GetNamespaceGroup(namespace, name); err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "rbac.UpdateNamespaceGroup", "group %q not found", name))
			return
		}

		var g Group
		if err := c.ShouldBindJSON(&g); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "rbac.UpdateNamespaceGroup", ""))
			return
		}
		g.Name = name
		if err := resolveNamespace(&g.Metadata, namespace); err != nil {
			httpapi.Fail(c, err)
			return
		}

		if err := repo.PutNamespaceGroup(namespace, g); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.UpdateNamespaceGroup", ""))
			return
		}
		c.JSON(http.StatusOK, g)
	})

	group.DELETE("/groups/:group", RequireClusterRBAC(repo, AuthorizationAPI, "groups", "delete"), func(c *gin.Context) {
		namespace, name := c.Param("namespace"), c.Param("group")
		if _, err := repo.GetNamespaceGroup(namespace, name); err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "rbac.DeleteNamespaceGroup", "group %q not found", name))
			return
		}
		if err := repo.DeleteNamespaceGroup(namespace, name); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.DeleteNamespaceGroup", ""))
			return
		}
		c.Status(http.StatusNoContent)
	})

	// --- roles ---

	group.POST("/roles", RequireClusterRBAC(repo, AuthorizationAPI, "roles", "create"), func(c *gin.Context) {
		namespace := c.Param("namespace")

		var role Role
		if err := c.ShouldBindJSON(&role); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "rbac.CreateNamespaceRole", ""))
			return
		}
		if role.Name == "" {
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, "rbac.CreateNamespaceRole", "name is required"))
			return
		}
		if err := resolveNamespace(&role.Metadata, namespace); err != nil {
			httpapi.Fail(c, err)
			return
		}

		if err := repo.PutNamespaceRole(namespace, role); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.CreateNamespaceRole", ""))
			return
		}
		c.JSON(http.StatusCreated, role)
	})

	group.GET("/roles", RequireClusterRBAC(repo, AuthorizationAPI, "roles", "list"), func(c *gin.Context) {
		roles, err := repo.ListNamespaceRoles(c.Param("namespace"))
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.ListNamespaceRoles", ""))
			return
		}
		c.JSON(http.StatusOK, roles)
	})

	group.GET("/roles/:role", RequireClusterRBAC(repo, AuthorizationAPI, "roles", "get"), func(c *gin.Context) {
		namespace, name := c.Param("namespace"), c.Param("role")
		role, err := repo.GetNamespaceRole(namespace, name)
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "rbac.GetNamespaceRole", "role %q not found", name))
			return
		}
		c.JSON(http.StatusOK, role)
	})

	group.PUT("/roles/:role", RequireClusterRBAC(repo, AuthorizationAPI, "roles", "update"), func(c *gin.Context) {
		namespace, name := c.Param("namespace"), c.Param("role")
		if _, err := repo.GetNamespaceRole(namespace, name); err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "rbac.UpdateNamespaceRole", "role %q not found", name))
			return
		}

		var role Role
		if err := c.ShouldBindJSON(&role); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "rbac.UpdateNamespaceRole", ""))
			return
		}
		role.Name = name
		if err := resolveNamespace(&role.Metadata, namespace); err != nil {
			httpapi.Fail(c, err)
			return
		}

		if err := repo.PutNamespaceRole(namespace, role); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.UpdateNamespaceRole", ""))
			return
		}
		c.JSON(http.StatusOK, role)
	})

	group.DELETE("/roles/:role", RequireClusterRBAC(repo, AuthorizationAPI, "roles", "delete"), func(c *gin.Context) {
		namespace, name := c.Param("namespace"), c.Param("role")
		if _, err := repo.GetNamespaceRole(namespace, name); err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "rbac.DeleteNamespaceRole", "role %q not found", name))
			return
		}
		if err := repo.DeleteNamespaceRole(namespace, name); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.DeleteNamespaceRole", ""))
			return
		}
		c.Status(http.StatusNoContent)
	})

	// --- rolebindings ---

	group.POST("/rolebindings", RequireClusterRBAC(repo, AuthorizationAPI, "rolebindings", "create"), func(c *gin.Context) {
		namespace := c.Param("namespace")

		var rb RoleBinding
		if err := c.ShouldBindJSON(&rb); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "rbac.CreateNamespaceRoleBinding", ""))
			return
		}
		if rb.Name == "" || rb.Role == "" {
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, "rbac.CreateNamespaceRoleBinding", "name and role are required"))
			return
		}
		if err := resolveNamespace(&rb.Metadata, namespace); err != nil {
			httpapi.Fail(c, err)
			return
		}
		if err := validateNamespaceRoleBinding(repo, namespace, rb); err != nil {
			httpapi.Fail(c, err)
			return
		}

		if err := repo.PutNamespaceRoleBinding(namespace, rb); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.CreateNamespaceRoleBinding", ""))
			return
		}
		c.JSON(http.StatusCreated, rb)
	})

	group.GET("/rolebindings", RequireClusterRBAC(repo, AuthorizationAPI, "rolebindings", "list"), func(c *gin.Context) {
		bindings, err := repo.ListNamespaceRoleBindings(c.Param("namespace"))
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.ListNamespaceRoleBindings", ""))
			return
		}
		c.JSON(http.StatusOK, bindings)
	})

	group.GET("/rolebindings/:rolebinding", RequireClusterRBAC(repo, AuthorizationAPI, "rolebindings", "get"), func(c *gin.Context) {
		namespace, name := c.Param("namespace"), c.Param("rolebinding")
		rb, err := repo.GetNamespaceRoleBinding(namespace, name)
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "rbac.GetNamespaceRoleBinding", "rolebinding %q not found", name))
			return
		}
		c.JSON(http.StatusOK, rb)
	})

	group.PUT("/rolebindings/:rolebinding", RequireClusterRBAC(repo, AuthorizationAPI, "rolebindings", "update"), func(c *gin.Context) {
		namespace, name := c.Param("namespace"), c.Param("rolebinding")
		if _, err := repo.GetNamespaceRoleBinding(namespace, name); err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "rbac.UpdateNamespaceRoleBinding", "rolebinding %q not found", name))
			return
		}

		var rb RoleBinding
		if err := c.ShouldBindJSON(&rb); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "rbac.UpdateNamespaceRoleBinding", ""))
			return
		}
		rb.Name = name
		if rb.Role == "" {
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, "rbac.UpdateNamespaceRoleBinding", "role is required"))
			return
		}
		if err := resolveNamespace(&rb.Metadata, namespace); err != nil {
			httpapi.Fail(c, err)
			return
		}
		if err := validateNamespaceRoleBinding(repo, namespace, rb); err != nil {
			httpapi.Fail(c, err)
			return
		}

		if err := repo.PutNamespaceRoleBinding(namespace, rb); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.UpdateNamespaceRoleBinding", ""))
			return
		}
		c.JSON(http.StatusOK, rb)
	})

	group.DELETE("/rolebindings/:rolebinding", RequireClusterRBAC(repo, AuthorizationAPI, "rolebindings", "delete"), func(c *gin.Context) {
		namespace, name := c.Param("namespace"), c.Param("rolebinding")
		if _, err := repo.GetNamespaceRoleBinding(namespace, name); err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "rbac.DeleteNamespaceRoleBinding", "rolebinding %q not found", name))
			return
		}
		if err := repo.DeleteNamespaceRoleBinding(namespace, name); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "rbac.DeleteNamespaceRoleBinding", ""))
			return
		}
		c.Status(http.StatusNoContent)
	})
}
