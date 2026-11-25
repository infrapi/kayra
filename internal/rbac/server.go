package rbac

import (
	"context"
	"crypto/rsa"
	"net/http"
	"time"

	"github.com/infrapi/kayra/internal/audit"
	gconfig "github.com/infrapi/kayra/internal/config"
	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/middleware"
	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// ServerOptions configure the Server.
type ServerOptions struct {
	// Repo holds the RBAC objects and service accounts.
	Repo *Repository
	// ValidateClusterRoleRules, when non-nil, vets a global cluster role's
	// rules (catalog.Repository.ValidateClusterRoleRules: the apis'
	// cluster-scoped resources); ValidateRoleRules a namespace role's
	// (catalog.Repository.ValidateRoleRules). Their error is answered
	// as it is.
	ValidateClusterRoleRules func([]Rule) *liberrors.Error
	ValidateRoleRules        func([]Rule) *liberrors.Error
	// Tokens configures the service accounts' token action.
	Tokens ServiceAccountTokens
	// Prechecks are /check's catalog-owned steps.
	Prechecks Prechecks
	// Auditor records every /check decision: none when nil.
	Auditor *audit.Auditor
	// PATs configures the personal access tokens.
	PATs PATOptions
}

// PATOptions configure the personal access tokens.
type PATOptions struct {
	Store store.Store
	Keys  store.Keys
	// Pub encrypts the token records.
	Pub *rsa.PublicKey
	// Config tells a claims-backed authorization backend, whose groups are
	// snapshotted into the record.
	Config *gconfig.Config
	// TTLs are a token's default and longest lifetimes.
	TTLs gconfig.PatDurations
	// CanManageOthers tells whether the caller may list (verb list), read
	// (get) or revoke (delete) another user's tokens: never when nil.
	CanManageOthers func(ac *middleware.AuthContext, verb string) bool
	// Now is the clock: time.Now when nil.
	Now func() time.Time
}

// Server is the rbac API, the authorization group: every operation of its
// contract, api/rbac-v1.yaml, mounted by Register. Its methods decide who
// may, as the routes' gates did: the cluster RBAC for the cluster objects,
// CanManageNamespaceRBAC for a namespace's, any authenticated caller for
// /check and their own tokens.
type Server struct {
	o    ServerOptions
	repo *Repository
}

var _ Handlers = (*Server)(nil)

// NewServer is the rbac API of o.
func NewServer(o ServerOptions) *Server {
	if o.PATs.Now == nil {
		o.PATs.Now = time.Now
	}
	return &Server{o: o, repo: o.Repo}
}

// fromAPI is a request's body, an api type, as rbac's own: written the
// same.
func fromAPI[T any](v any, origin string) (T, error) {
	out, err := httpapi.Convert[T](v)
	if err != nil {
		return out, liberrors.Wrap(err, http.StatusBadRequest, origin, "")
	}
	return out, nil
}

// toAPI is one of rbac's objects as its api type.
func toAPI[T any](v any, origin string) (T, error) {
	out, err := httpapi.Convert[T](v)
	if err != nil {
		return out, liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
	}
	return out, nil
}

// internal is an unexpected failure, a store's.
func internal(err error, origin string) error {
	return liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
}

// cluster decides a cluster object's request on the cluster RBAC.
func (s *Server) cluster(ctx context.Context) error {
	return s.repo.AuthorizeClusterRequest(ctx)
}

// namespace decides managing resource in namespace.
func (s *Server) namespace(ctx context.Context, namespace, resource, verb string) error {
	return s.repo.AuthorizeNamespaceRBAC(ctx, namespace, AuthorizationAPI, resource, verb)
}
