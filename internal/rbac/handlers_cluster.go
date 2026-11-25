package rbac

import (
	"context"
	"net/http"

	"github.com/infrapi/kayra/api"
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

// The cluster RBAC objects, /apis/authorization.infrapi.io/v1/
// {clustergroups,clusterroles,clusterrolebindings}: cluster-scoped
// siblings of the namespace groups/roles/rolebindings, "cluster" folded
// into the resource name, as Kubernetes names ClusterRole. The cluster
// RBAC they define decides who manages them (AuthorizeClusterRequest), the
// built-in sysadmin binding (Repository.SetSysadmin) first. A cluster
// object is global when its metadata.namespace is "": it grants
// cluster-scoped resources only; otherwise it is scoped to that namespace,
// and grants managing it (CanManageNamespaceRBAC).
//
// Writes follow the anti-escalation rule: a cluster role, or a binding to
// one, may grant only what its writer holds on the cluster
// (ClusterRules), unless they hold escalate on clusterroles, or bind on
// clusterrolebindings. ValidateClusterRoleRules checks a global cluster
// role's rules against the apis' cluster-scoped resources.

// grantCluster checks what a cluster role, or a binding to one, grants
// against what the caller holds on the cluster.
func (s *Server) grantCluster(ctx context.Context, role Role, resource, verb, origin string) error {
	if role.Metadata.Namespace == "" && resource == "clusterroles" && s.o.ValidateClusterRoleRules != nil {
		if err := s.o.ValidateClusterRoleRules(role.Rules); err != nil {
			return err
		}
	}
	ac, err := Caller(ctx, origin)
	if err != nil {
		return err
	}
	have, err := s.repo.ClusterRules(ac.UserID, ac.Groups)
	if err != nil {
		return internal(err, origin)
	}
	return httpapi.Err(checkGrant(have, role.Rules, resource, verb, origin))
}

// --- clustergroups ---

func (s *Server) CreateClusterGroup(ctx context.Context, body api.Group) (api.Group, error) {
	const origin = "rbac.CreateClusterGroup"
	if err := s.cluster(ctx); err != nil {
		return api.Group{}, err
	}
	g, err := fromAPI[Group](body, origin)
	if err != nil {
		return api.Group{}, err
	}
	if g.Name == "" {
		return api.Group{}, liberrors.New(http.StatusBadRequest, origin, "name is required")
	}
	if err := validateGroupMembers(g, true, origin); err != nil {
		return api.Group{}, err
	}
	if err := s.repo.PutClusterGroup(&g); err != nil {
		return api.Group{}, internal(err, origin)
	}
	return toAPI[api.Group](g, origin)
}

func (s *Server) ListClusterGroups(ctx context.Context) ([]api.Group, error) {
	const origin = "rbac.ListClusterGroups"
	if err := s.cluster(ctx); err != nil {
		return nil, err
	}
	groups, err := s.repo.ListClusterGroups()
	if err != nil {
		return nil, internal(err, origin)
	}
	return toAPI[[]api.Group](groups, origin)
}

func (s *Server) GetClusterGroup(ctx context.Context, name string) (api.Group, error) {
	const origin = "rbac.GetClusterGroup"
	if err := s.cluster(ctx); err != nil {
		return api.Group{}, err
	}
	g, err := s.repo.GetClusterGroup(name)
	if err != nil {
		return api.Group{}, notFoundOrInternal(err, origin, "group %q not found", name)
	}
	return toAPI[api.Group](g, origin)
}

func (s *Server) UpdateClusterGroup(ctx context.Context, name string, body api.Group) (api.Group, error) {
	const origin = "rbac.UpdateClusterGroup"
	if err := s.cluster(ctx); err != nil {
		return api.Group{}, err
	}
	if _, err := s.repo.GetClusterGroup(name); err != nil {
		return api.Group{}, notFoundOrInternal(err, origin, "group %q not found", name)
	}
	g, err := fromAPI[Group](body, origin)
	if err != nil {
		return api.Group{}, err
	}
	g.Name = name
	if err := validateGroupMembers(g, true, origin); err != nil {
		return api.Group{}, err
	}
	if err := s.repo.PutClusterGroup(&g); err != nil {
		return api.Group{}, internal(err, origin)
	}
	return toAPI[api.Group](g, origin)
}

func (s *Server) DeleteClusterGroup(ctx context.Context, name string) error {
	const origin = "rbac.DeleteClusterGroup"
	if err := s.cluster(ctx); err != nil {
		return err
	}
	if _, err := s.repo.GetClusterGroup(name); err != nil {
		return notFoundOrInternal(err, origin, "group %q not found", name)
	}
	if err := s.repo.DeleteClusterGroup(name); err != nil {
		return internal(err, origin)
	}
	return nil
}

// --- clusterroles ---

func (s *Server) CreateClusterRole(ctx context.Context, body api.Role) (api.Role, error) {
	const origin = "rbac.CreateClusterRole"
	if err := s.cluster(ctx); err != nil {
		return api.Role{}, err
	}
	role, err := fromAPI[Role](body, origin)
	if err != nil {
		return api.Role{}, err
	}
	if role.Name == "" {
		return api.Role{}, liberrors.New(http.StatusBadRequest, origin, "name is required")
	}
	if err := s.grantCluster(ctx, role, "clusterroles", VerbEscalate, origin); err != nil {
		return api.Role{}, err
	}
	if err := s.repo.PutClusterRole(&role); err != nil {
		return api.Role{}, internal(err, origin)
	}
	return toAPI[api.Role](role, origin)
}

func (s *Server) ListClusterRoles(ctx context.Context) ([]api.Role, error) {
	const origin = "rbac.ListClusterRoles"
	if err := s.cluster(ctx); err != nil {
		return nil, err
	}
	roles, err := s.repo.ListClusterRoles()
	if err != nil {
		return nil, internal(err, origin)
	}
	return toAPI[[]api.Role](roles, origin)
}

func (s *Server) GetClusterRole(ctx context.Context, name string) (api.Role, error) {
	const origin = "rbac.GetClusterRole"
	if err := s.cluster(ctx); err != nil {
		return api.Role{}, err
	}
	role, err := s.repo.GetClusterRole(name)
	if err != nil {
		return api.Role{}, notFoundOrInternal(err, origin, "role %q not found", name)
	}
	return toAPI[api.Role](role, origin)
}

func (s *Server) UpdateClusterRole(ctx context.Context, name string, body api.Role) (api.Role, error) {
	const origin = "rbac.UpdateClusterRole"
	if err := s.cluster(ctx); err != nil {
		return api.Role{}, err
	}
	if _, err := s.repo.GetClusterRole(name); err != nil {
		return api.Role{}, notFoundOrInternal(err, origin, "role %q not found", name)
	}
	role, err := fromAPI[Role](body, origin)
	if err != nil {
		return api.Role{}, err
	}
	role.Name = name
	if err := s.grantCluster(ctx, role, "clusterroles", VerbEscalate, origin); err != nil {
		return api.Role{}, err
	}
	if err := s.repo.PutClusterRole(&role); err != nil {
		return api.Role{}, internal(err, origin)
	}
	return toAPI[api.Role](role, origin)
}

func (s *Server) DeleteClusterRole(ctx context.Context, name string) error {
	const origin = "rbac.DeleteClusterRole"
	if err := s.cluster(ctx); err != nil {
		return err
	}
	if _, err := s.repo.GetClusterRole(name); err != nil {
		return notFoundOrInternal(err, origin, "role %q not found", name)
	}
	if err := s.repo.DeleteClusterRole(name); err != nil {
		return internal(err, origin)
	}
	return nil
}

// --- clusterrolebindings ---

func (s *Server) CreateClusterRoleBinding(ctx context.Context, body api.RoleBinding) (api.RoleBinding, error) {
	const origin = "rbac.CreateClusterRoleBinding"
	if err := s.cluster(ctx); err != nil {
		return api.RoleBinding{}, err
	}
	rb, err := fromAPI[RoleBinding](body, origin)
	if err != nil {
		return api.RoleBinding{}, err
	}
	if rb.Name == "" || rb.Role == "" {
		return api.RoleBinding{}, liberrors.New(http.StatusBadRequest, origin, "name and role are required")
	}
	if err := s.writeClusterRoleBinding(ctx, &rb, origin); err != nil {
		return api.RoleBinding{}, err
	}
	return toAPI[api.RoleBinding](rb, origin)
}

// writeClusterRoleBinding validates rb, checks what its role grants
// against the caller's, and writes it.
func (s *Server) writeClusterRoleBinding(ctx context.Context, rb *RoleBinding, origin string) error {
	if err := validateClusterRoleBinding(s.repo, *rb); err != nil {
		return err
	}
	role, _ := s.repo.GetClusterRole(rb.Role)
	if err := s.grantCluster(ctx, role, "clusterrolebindings", VerbBind, origin); err != nil {
		return err
	}
	if err := s.repo.PutClusterRoleBinding(rb); err != nil {
		return internal(err, origin)
	}
	return nil
}

func (s *Server) ListClusterRoleBindings(ctx context.Context) ([]api.RoleBinding, error) {
	const origin = "rbac.ListClusterRoleBindings"
	if err := s.cluster(ctx); err != nil {
		return nil, err
	}
	bindings, err := s.repo.ListClusterRoleBindings()
	if err != nil {
		return nil, internal(err, origin)
	}
	return toAPI[[]api.RoleBinding](bindings, origin)
}

func (s *Server) GetClusterRoleBinding(ctx context.Context, name string) (api.RoleBinding, error) {
	const origin = "rbac.GetClusterRoleBinding"
	if err := s.cluster(ctx); err != nil {
		return api.RoleBinding{}, err
	}
	rb, err := s.repo.GetClusterRoleBinding(name)
	if err != nil {
		return api.RoleBinding{}, notFoundOrInternal(err, origin, "rolebinding %q not found", name)
	}
	return toAPI[api.RoleBinding](rb, origin)
}

func (s *Server) UpdateClusterRoleBinding(ctx context.Context, name string, body api.RoleBinding) (api.RoleBinding, error) {
	const origin = "rbac.UpdateClusterRoleBinding"
	if err := s.cluster(ctx); err != nil {
		return api.RoleBinding{}, err
	}
	if _, err := s.repo.GetClusterRoleBinding(name); err != nil {
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
	if err := s.writeClusterRoleBinding(ctx, &rb, origin); err != nil {
		return api.RoleBinding{}, err
	}
	return toAPI[api.RoleBinding](rb, origin)
}

func (s *Server) DeleteClusterRoleBinding(ctx context.Context, name string) error {
	const origin = "rbac.DeleteClusterRoleBinding"
	if err := s.cluster(ctx); err != nil {
		return err
	}
	if _, err := s.repo.GetClusterRoleBinding(name); err != nil {
		return notFoundOrInternal(err, origin, "rolebinding %q not found", name)
	}
	if err := s.repo.DeleteClusterRoleBinding(name); err != nil {
		return internal(err, origin)
	}
	return nil
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
