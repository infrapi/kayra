package rbac

import (
	"context"
	"net/http"

	"github.com/infrapi/kayra/api"
	"github.com/infrapi/kayra/internal/httpapi"
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

// grantNamespace refuses a namespace role, or a binding to one, granting
// what the caller does not hold in namespace (NamespaceRules), unless
// they hold escalate on roles, or bind on rolebindings: the
// anti-escalation rule, in a namespace.
func (s *Server) grantNamespace(ctx context.Context, namespace string, rules []Rule, resource, verb, origin string) error {
	ac, err := Caller(ctx, origin)
	if err != nil {
		return err
	}
	have, err := s.repo.NamespaceRules(ac.UserID, ac.Groups, namespace)
	if err != nil {
		return internal(err, origin)
	}
	return httpapi.Err(checkGrant(have, rules, resource, verb, origin))
}

// The namespace RBAC objects, /apis/authorization.infrapi.io/v1/
// namespaces/:namespace/{groups,roles,rolebindings}: what a namespace's
// members may do there. Only a caller whose cluster group membership
// grants them AuthorizationAPI rights in this namespace manages them
// (CanManageNamespaceRBAC), the spec's bootstrap flow. ValidateRoleRules
// vets a namespace role's rules before it is written: every api
// registered, every resource and verb one its OpenAPI spec serves.

// --- groups ---

func (s *Server) CreateGroup(ctx context.Context, namespace string, body api.Group) (api.Group, error) {
	const origin = "rbac.CreateNamespaceGroup"
	if err := s.namespace(ctx, namespace, "groups", "create"); err != nil {
		return api.Group{}, err
	}
	g, err := fromAPI[Group](body, origin)
	if err != nil {
		return api.Group{}, err
	}
	if g.Name == "" {
		return api.Group{}, liberrors.New(http.StatusBadRequest, origin, "name is required")
	}
	if err := s.writeGroup(namespace, &g, origin); err != nil {
		return api.Group{}, err
	}
	return toAPI[api.Group](g, origin)
}

// writeGroup resolves g's namespace, validates its members, and writes it.
func (s *Server) writeGroup(namespace string, g *Group, origin string) error {
	if err := resolveNamespace(&g.Metadata, namespace); err != nil {
		return err
	}
	if err := validateGroupMembers(*g, false, origin); err != nil {
		return err
	}
	if err := s.repo.PutNamespaceGroup(namespace, g); err != nil {
		return internal(err, origin)
	}
	return nil
}

func (s *Server) ListGroups(ctx context.Context, namespace string) ([]api.Group, error) {
	const origin = "rbac.ListNamespaceGroups"
	if err := s.namespace(ctx, namespace, "groups", "list"); err != nil {
		return nil, err
	}
	groups, err := s.repo.ListNamespaceGroups(namespace)
	if err != nil {
		return nil, internal(err, origin)
	}
	return toAPI[[]api.Group](groups, origin)
}

func (s *Server) GetGroup(ctx context.Context, namespace, name string) (api.Group, error) {
	const origin = "rbac.GetNamespaceGroup"
	if err := s.namespace(ctx, namespace, "groups", "get"); err != nil {
		return api.Group{}, err
	}
	g, err := s.repo.GetNamespaceGroup(namespace, name)
	if err != nil {
		return api.Group{}, notFoundOrInternal(err, origin, "group %q not found", name)
	}
	return toAPI[api.Group](g, origin)
}

func (s *Server) UpdateGroup(ctx context.Context, namespace, name string, body api.Group) (api.Group, error) {
	const origin = "rbac.UpdateNamespaceGroup"
	if err := s.namespace(ctx, namespace, "groups", "update"); err != nil {
		return api.Group{}, err
	}
	if _, err := s.repo.GetNamespaceGroup(namespace, name); err != nil {
		return api.Group{}, notFoundOrInternal(err, origin, "group %q not found", name)
	}
	g, err := fromAPI[Group](body, origin)
	if err != nil {
		return api.Group{}, err
	}
	g.Name = name
	if err := s.writeGroup(namespace, &g, origin); err != nil {
		return api.Group{}, err
	}
	return toAPI[api.Group](g, origin)
}

func (s *Server) DeleteGroup(ctx context.Context, namespace, name string) error {
	const origin = "rbac.DeleteNamespaceGroup"
	if err := s.namespace(ctx, namespace, "groups", "delete"); err != nil {
		return err
	}
	if _, err := s.repo.GetNamespaceGroup(namespace, name); err != nil {
		return notFoundOrInternal(err, origin, "group %q not found", name)
	}
	if err := s.repo.DeleteNamespaceGroup(namespace, name); err != nil {
		return internal(err, origin)
	}
	return nil
}

// --- roles ---

func (s *Server) CreateRole(ctx context.Context, namespace string, body api.Role) (api.Role, error) {
	const origin = "rbac.CreateNamespaceRole"
	if err := s.namespace(ctx, namespace, "roles", "create"); err != nil {
		return api.Role{}, err
	}
	role, err := fromAPI[Role](body, origin)
	if err != nil {
		return api.Role{}, err
	}
	if role.Name == "" {
		return api.Role{}, liberrors.New(http.StatusBadRequest, origin, "name is required")
	}
	if err := s.writeRole(ctx, namespace, &role, origin); err != nil {
		return api.Role{}, err
	}
	return toAPI[api.Role](role, origin)
}

// writeRole resolves role's namespace, vets its rules, checks them against
// the caller's, and writes it.
func (s *Server) writeRole(ctx context.Context, namespace string, role *Role, origin string) error {
	if err := resolveNamespace(&role.Metadata, namespace); err != nil {
		return err
	}
	if s.o.ValidateRoleRules != nil {
		if err := s.o.ValidateRoleRules(role.Rules); err != nil {
			return err
		}
	}
	if err := s.grantNamespace(ctx, namespace, role.Rules, "roles", VerbEscalate, origin); err != nil {
		return err
	}
	if err := s.repo.PutNamespaceRole(namespace, role); err != nil {
		return internal(err, origin)
	}
	return nil
}

func (s *Server) ListRoles(ctx context.Context, namespace string) ([]api.Role, error) {
	const origin = "rbac.ListNamespaceRoles"
	if err := s.namespace(ctx, namespace, "roles", "list"); err != nil {
		return nil, err
	}
	roles, err := s.repo.ListNamespaceRoles(namespace)
	if err != nil {
		return nil, internal(err, origin)
	}
	return toAPI[[]api.Role](roles, origin)
}

func (s *Server) GetRole(ctx context.Context, namespace, name string) (api.Role, error) {
	const origin = "rbac.GetNamespaceRole"
	if err := s.namespace(ctx, namespace, "roles", "get"); err != nil {
		return api.Role{}, err
	}
	role, err := s.repo.GetNamespaceRole(namespace, name)
	if err != nil {
		return api.Role{}, notFoundOrInternal(err, origin, "role %q not found", name)
	}
	return toAPI[api.Role](role, origin)
}

func (s *Server) UpdateRole(ctx context.Context, namespace, name string, body api.Role) (api.Role, error) {
	const origin = "rbac.UpdateNamespaceRole"
	if err := s.namespace(ctx, namespace, "roles", "update"); err != nil {
		return api.Role{}, err
	}
	if _, err := s.repo.GetNamespaceRole(namespace, name); err != nil {
		return api.Role{}, notFoundOrInternal(err, origin, "role %q not found", name)
	}
	role, err := fromAPI[Role](body, origin)
	if err != nil {
		return api.Role{}, err
	}
	role.Name = name
	if err := s.writeRole(ctx, namespace, &role, origin); err != nil {
		return api.Role{}, err
	}
	return toAPI[api.Role](role, origin)
}

func (s *Server) DeleteRole(ctx context.Context, namespace, name string) error {
	const origin = "rbac.DeleteNamespaceRole"
	if err := s.namespace(ctx, namespace, "roles", "delete"); err != nil {
		return err
	}
	if _, err := s.repo.GetNamespaceRole(namespace, name); err != nil {
		return notFoundOrInternal(err, origin, "role %q not found", name)
	}
	if err := s.repo.DeleteNamespaceRole(namespace, name); err != nil {
		return internal(err, origin)
	}
	return nil
}

// --- rolebindings ---

func (s *Server) CreateRoleBinding(ctx context.Context, namespace string, body api.RoleBinding) (api.RoleBinding, error) {
	const origin = "rbac.CreateNamespaceRoleBinding"
	if err := s.namespace(ctx, namespace, "rolebindings", "create"); err != nil {
		return api.RoleBinding{}, err
	}
	rb, err := fromAPI[RoleBinding](body, origin)
	if err != nil {
		return api.RoleBinding{}, err
	}
	if rb.Name == "" || rb.Role == "" {
		return api.RoleBinding{}, liberrors.New(http.StatusBadRequest, origin, "name and role are required")
	}
	if err := s.writeRoleBinding(ctx, namespace, &rb, origin); err != nil {
		return api.RoleBinding{}, err
	}
	return toAPI[api.RoleBinding](rb, origin)
}

// writeRoleBinding resolves rb's namespace, validates it, checks what its
// role grants against the caller's, and writes it.
func (s *Server) writeRoleBinding(ctx context.Context, namespace string, rb *RoleBinding, origin string) error {
	if err := resolveNamespace(&rb.Metadata, namespace); err != nil {
		return err
	}
	if err := validateNamespaceRoleBinding(s.repo, namespace, *rb); err != nil {
		return err
	}
	role, _ := s.repo.GetNamespaceRole(namespace, rb.Role)
	if err := s.grantNamespace(ctx, namespace, role.Rules, "rolebindings", VerbBind, origin); err != nil {
		return err
	}
	if err := s.repo.PutNamespaceRoleBinding(namespace, rb); err != nil {
		return internal(err, origin)
	}
	return nil
}

func (s *Server) ListRoleBindings(ctx context.Context, namespace string) ([]api.RoleBinding, error) {
	const origin = "rbac.ListNamespaceRoleBindings"
	if err := s.namespace(ctx, namespace, "rolebindings", "list"); err != nil {
		return nil, err
	}
	bindings, err := s.repo.ListNamespaceRoleBindings(namespace)
	if err != nil {
		return nil, internal(err, origin)
	}
	return toAPI[[]api.RoleBinding](bindings, origin)
}

func (s *Server) GetRoleBinding(ctx context.Context, namespace, name string) (api.RoleBinding, error) {
	const origin = "rbac.GetNamespaceRoleBinding"
	if err := s.namespace(ctx, namespace, "rolebindings", "get"); err != nil {
		return api.RoleBinding{}, err
	}
	rb, err := s.repo.GetNamespaceRoleBinding(namespace, name)
	if err != nil {
		return api.RoleBinding{}, notFoundOrInternal(err, origin, "rolebinding %q not found", name)
	}
	return toAPI[api.RoleBinding](rb, origin)
}

func (s *Server) UpdateRoleBinding(ctx context.Context, namespace, name string, body api.RoleBinding) (api.RoleBinding, error) {
	const origin = "rbac.UpdateNamespaceRoleBinding"
	if err := s.namespace(ctx, namespace, "rolebindings", "update"); err != nil {
		return api.RoleBinding{}, err
	}
	if _, err := s.repo.GetNamespaceRoleBinding(namespace, name); err != nil {
		return api.RoleBinding{}, notFoundOrInternal(err, origin, "rolebinding %q not found", name)
	}
	rb, err := fromAPI[RoleBinding](body, origin)
	if err != nil {
		return api.RoleBinding{}, err
	}
	rb.Name = name
	if rb.Role == "" {
		return api.RoleBinding{}, liberrors.New(http.StatusBadRequest, origin, "role is required")
	}
	if err := s.writeRoleBinding(ctx, namespace, &rb, origin); err != nil {
		return api.RoleBinding{}, err
	}
	return toAPI[api.RoleBinding](rb, origin)
}

func (s *Server) DeleteRoleBinding(ctx context.Context, namespace, name string) error {
	const origin = "rbac.DeleteNamespaceRoleBinding"
	if err := s.namespace(ctx, namespace, "rolebindings", "delete"); err != nil {
		return err
	}
	if _, err := s.repo.GetNamespaceRoleBinding(namespace, name); err != nil {
		return notFoundOrInternal(err, origin, "rolebinding %q not found", name)
	}
	if err := s.repo.DeleteNamespaceRoleBinding(namespace, name); err != nil {
		return internal(err, origin)
	}
	return nil
}
