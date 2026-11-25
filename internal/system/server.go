// Package system is Kayra's system API, api/system-v1.yaml: the
// namespaces, the unit of isolation every other API's resources, RBAC and
// subscriptions live in.
package system

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/infrapi/kayra/api"
	"github.com/infrapi/kayra/internal/catalog"
	"github.com/infrapi/kayra/internal/rbac"
	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// Server is the system API. Its writes (create, delete) are decided on the
// cluster RBAC; its reads let whoever the cluster RBAC grants the verb on
// namespaces see every one, anyone else the namespaces they are a member
// of, whatever their roles there. Mount it with Register, behind the
// authenticator and httpapi.WithRequest.
type Server struct {
	repo *catalog.Repository
	rbac *rbac.Repository
}

var _ Handlers = (*Server)(nil)

// NewServer is the system API of repo's namespaces, decided on rbacRepo.
func NewServer(repo *catalog.Repository, rbacRepo *rbac.Repository) *Server {
	return &Server{repo: repo, rbac: rbacRepo}
}

// visible tells, for verb on namespaces, whether the caller sees every
// namespace, and otherwise whether they see one: when they are a member.
func (s *Server) visible(ctx context.Context, verb, origin string) (all bool, member func(namespace string) (bool, error), err error) {
	ac, err := rbac.Caller(ctx, origin)
	if err != nil {
		return false, nil, err
	}
	all, _, err = s.rbac.AuthorizeCluster(ac.UserID, ac.Groups, catalog.SystemAPI, "namespaces", verb)
	if all || err != nil {
		return all, nil, err
	}
	if verb == "get" {
		return false, func(ns string) (bool, error) { return s.rbac.IsNamespaceMember(ns, ac.UserID, ac.Groups) }, nil
	}
	members, err := s.rbac.MemberNamespaces(ac.UserID, ac.Groups)
	return false, func(ns string) (bool, error) { return members[ns], nil }, err
}

func namespaceOf(n catalog.Namespace) api.Namespace {
	return api.Namespace{Name: n.Name, Active: n.Active, CreatedAt: n.CreatedAt, UpdatedAt: n.UpdatedAt}
}

func notFoundOrInternal(err error, origin, format string, args ...any) *liberrors.Error {
	if errors.Is(err, store.ErrNotFound) {
		return liberrors.New(http.StatusNotFound, origin, format, args...)
	}
	return liberrors.Wrap(err, http.StatusInternalServerError, origin, format, args...)
}

// ListNamespaces is the namespaces the caller sees, by name.
func (s *Server) ListNamespaces(ctx context.Context) ([]api.Namespace, error) {
	const origin = "system.ListNamespaces"
	all, member, err := s.visible(ctx, "list", origin)
	if err != nil {
		return nil, internal(err, origin)
	}
	namespaces, err := s.repo.ListNamespaces()
	if err != nil {
		return nil, liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
	}
	slices.SortFunc(namespaces, func(a, b catalog.Namespace) int { return strings.Compare(a.Name, b.Name) })
	out := make([]api.Namespace, 0, len(namespaces))
	for _, n := range namespaces {
		if !all {
			in, err := member(n.Name)
			if err != nil {
				return nil, liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
			}
			if !in {
				continue
			}
		}
		out = append(out, namespaceOf(n))
	}
	return out, nil
}

// CreateNamespace creates a namespace, inactive until the reconciler
// provisions it: no request field makes it active.
func (s *Server) CreateNamespace(ctx context.Context, body api.Namespace) (api.Namespace, error) {
	const origin = "system.CreateNamespace"
	if err := s.rbac.AuthorizeClusterRequest(ctx); err != nil {
		return api.Namespace{}, err
	}
	if body.Name == "" {
		return api.Namespace{}, liberrors.New(http.StatusBadRequest, origin, "name is required")
	}
	n := catalog.Namespace{Name: body.Name, Active: false}
	if err := s.repo.PutNamespace(&n); err != nil {
		return api.Namespace{}, liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
	}
	return namespaceOf(n), nil
}

// GetNamespace is a namespace, for the cluster RBAC's readers and its
// members.
func (s *Server) GetNamespace(ctx context.Context, name string) (api.Namespace, error) {
	const origin = "system.GetNamespace"
	if _, err := rbac.Caller(ctx, origin); err != nil {
		return api.Namespace{}, err
	}
	n, err := s.repo.GetNamespace(name)
	if err != nil {
		return api.Namespace{}, notFoundOrInternal(err, origin, "namespace %q not found", name)
	}
	all, member, err := s.visible(ctx, "get", origin)
	if err == nil && !all {
		all, err = member(name)
		if err == nil && !all {
			return api.Namespace{}, liberrors.New(http.StatusForbidden, origin,
				"you are not a member of namespace %q: neither your user id nor any of your groups is listed in any of its groups", name).
				WithSolution("ask its admins to add you, or one of your groups, to one of its groups")
		}
	}
	if err != nil {
		return api.Namespace{}, internal(err, origin)
	}
	return namespaceOf(n), nil
}

// DeleteNamespace deletes a namespace.
func (s *Server) DeleteNamespace(ctx context.Context, name string) error {
	const origin = "system.DeleteNamespace"
	if err := s.rbac.AuthorizeClusterRequest(ctx); err != nil {
		return err
	}
	if _, err := s.repo.GetNamespace(name); err != nil {
		return notFoundOrInternal(err, origin, "namespace %q not found", name)
	}
	if err := s.repo.DeleteNamespace(name); err != nil {
		return liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
	}
	return nil
}

// internal is err as it is when it is an infrapi/lib error (a 401 say),
// a 500 otherwise.
func internal(err error, origin string) error {
	var lerr *liberrors.Error
	if errors.As(err, &lerr) {
		return lerr
	}
	return liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
}
