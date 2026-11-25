package rbac

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/infrapi/kayra/api"
	"github.com/infrapi/kayra/internal/identity"
	"github.com/infrapi/kayra/internal/middleware"
	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// validateGroupMembers refuses a group naming Kayra's own identities
// where they cannot be: a reserved user anywhere (a service account goes
// in ServiceAccounts), a reserved group other than its own namespace's
// service accounts' (a namespace group only), service accounts in a
// cluster group, a service account name that is no DNS label, and an API
// that is no API group.
func validateGroupMembers(g Group, cluster bool, origin string) *liberrors.Error {
	for _, u := range g.Users {
		if identity.IsReserved(u) {
			return liberrors.New(http.StatusBadRequest, origin, "users: %q: the %q prefix is Kayra's own", u, identity.Reserved).
				WithSolution("name a service account in serviceaccounts, in a group of its own namespace, an API in apis")
		}
	}
	for _, gr := range g.Groups {
		if !identity.IsReserved(gr) {
			continue
		}
		if cluster || gr != identity.NamespaceServiceAccounts(g.Metadata.Namespace) {
			return liberrors.New(http.StatusBadRequest, origin, "groups: %q: the only reserved group a group may name is its own namespace's service accounts', %q, in a namespace group",
				gr, identity.NamespaceServiceAccounts(g.Metadata.Namespace))
		}
	}
	if cluster && len(g.ServiceAccounts) > 0 {
		return liberrors.New(http.StatusBadRequest, origin, "serviceaccounts: a cluster group names none: a service account acts in its own namespace only").
			WithSolution("name it in a group of its namespace")
	}
	for _, name := range g.ServiceAccounts {
		if !identity.ValidName(name) {
			return liberrors.New(http.StatusBadRequest, origin, "serviceaccounts: %q: a service account of the group's namespace, by name (a DNS label)", name)
		}
	}
	for _, api := range g.APIs {
		if !identity.ValidAPIGroup(api) {
			return liberrors.New(http.StatusBadRequest, origin, "apis: %q: an API by its group, exactly, like compute.infrapi.io", api)
		}
	}
	return nil
}

// TokenIssuer signs a machine token: Kayra's authorization server
// (oauth2server.Server.IssueMachineToken). audience is its resources.
type TokenIssuer interface {
	// IssueMachineToken signs a token of subject, its uid and kind, for
	// audience, valid ttl.
	IssueMachineToken(subject, uid, kind string, audience []string, ttl time.Duration) (token string, expires time.Time, err error)
	// Resources are the audiences a token may be issued for, the first the
	// default.
	Resources() []string
	// AllowedResource tells whether a token may be issued for resource.
	AllowedResource(resource string) bool
}

// ServiceAccountTokens configures the token action: the issuer, nil when
// the authorization server is off (the action then answers 501), and the
// lifetimes.
type ServiceAccountTokens struct {
	Issuer     TokenIssuer
	DefaultTTL time.Duration
	MaxTTL     time.Duration
	// TrustedIssuer tells an issuer of federation.issuers: a federated
	// credential names one, or is refused. None is when nil.
	TrustedIssuer func(issuer string) bool
}

// validateServiceAccount refuses unsound keys and federated credentials
// (identity.CheckCredentials).
func validateServiceAccount(sa ServiceAccount, tokens ServiceAccountTokens, origin string) *liberrors.Error {
	err := identity.CheckCredentials(sa.JWKS, sa.FederatedCredentials, tokens.TrustedIssuer)
	if err == nil {
		return nil
	}
	e := liberrors.New(http.StatusBadRequest, origin, "%s", err)
	if errors.Is(err, identity.ErrUntrustedIssuer) {
		e = e.WithSolution("ask Kayra's admin to add it to federation.issuers")
	}
	return e
}

// ServiceAccountClient is a service account as a client of the token
// endpoint (client_credentials): its uid, its keys and its federated
// credentials. store.ErrNotFound when there is none.
func (r *Repository) ServiceAccountClient(subject string) (ServiceAccount, error) {
	namespace, name, ok := identity.ParseServiceAccount(subject)
	if !ok {
		return ServiceAccount{}, store.ErrNotFound
	}
	return r.GetNamespaceServiceAccount(namespace, name)
}

// A namespace's service accounts, /apis/authorization.infrapi.io/v1/
// namespaces/:namespace/serviceaccounts, decided as its other RBAC objects
// (CanManageNamespaceRBAC): create, list, get, update (its description,
// keys and federated credentials), delete, and the token action, POST
// .../serviceaccounts/:name/token, its own permission
// (serviceaccounts/token, create), whoever holds it acting with the
// service account's rights.

const serviceAccounts = "serviceaccounts"

func (s *Server) CreateServiceAccount(ctx context.Context, namespace string, body api.ServiceAccount) (api.ServiceAccount, error) {
	const origin = "rbac.CreateServiceAccount"
	if err := s.namespace(ctx, namespace, serviceAccounts, "create"); err != nil {
		return api.ServiceAccount{}, err
	}
	sa, err := fromAPI[ServiceAccount](body, origin)
	if err != nil {
		return api.ServiceAccount{}, err
	}
	if !identity.ValidName(sa.Name) {
		return api.ServiceAccount{}, liberrors.New(http.StatusBadRequest, origin, "name %q: a DNS label, lower case letters, digits and -", sa.Name)
	}
	if err := resolveNamespace(&sa.Metadata, namespace); err != nil {
		return api.ServiceAccount{}, err
	}
	if _, err := s.repo.GetNamespaceServiceAccount(namespace, sa.Name); err == nil {
		return api.ServiceAccount{}, liberrors.New(http.StatusConflict, origin, "service account %q exists in namespace %q", sa.Name, namespace)
	} else if !errors.Is(err, store.ErrNotFound) {
		return api.ServiceAccount{}, internal(err, origin)
	}
	if err := validateServiceAccount(sa, s.o.Tokens, origin); err != nil {
		return api.ServiceAccount{}, err
	}
	sa.UID = rand.Text()
	if err := s.repo.PutNamespaceServiceAccount(namespace, &sa); err != nil {
		return api.ServiceAccount{}, internal(err, origin)
	}
	return toAPI[api.ServiceAccount](sa, origin)
}

func (s *Server) ListServiceAccounts(ctx context.Context, namespace string) ([]api.ServiceAccount, error) {
	const origin = "rbac.ListServiceAccounts"
	if err := s.namespace(ctx, namespace, serviceAccounts, "list"); err != nil {
		return nil, err
	}
	sas, err := s.repo.ListNamespaceServiceAccounts(namespace)
	if err != nil {
		return nil, internal(err, origin)
	}
	return toAPI[[]api.ServiceAccount](sas, origin)
}

func (s *Server) GetServiceAccount(ctx context.Context, namespace, name string) (api.ServiceAccount, error) {
	const origin = "rbac.GetServiceAccount"
	if err := s.namespace(ctx, namespace, serviceAccounts, "get"); err != nil {
		return api.ServiceAccount{}, err
	}
	sa, err := s.repo.GetNamespaceServiceAccount(namespace, name)
	if err != nil {
		return api.ServiceAccount{}, notFoundOrInternal(err, origin, "service account %q not found", name)
	}
	return toAPI[api.ServiceAccount](sa, origin)
}

func (s *Server) UpdateServiceAccount(ctx context.Context, namespace, name string, body api.ServiceAccount) (api.ServiceAccount, error) {
	const origin = "rbac.UpdateServiceAccount"
	if err := s.namespace(ctx, namespace, serviceAccounts, "update"); err != nil {
		return api.ServiceAccount{}, err
	}
	old, err := s.repo.GetNamespaceServiceAccount(namespace, name)
	if err != nil {
		return api.ServiceAccount{}, notFoundOrInternal(err, origin, "service account %q not found", name)
	}
	sa, err := fromAPI[ServiceAccount](body, origin)
	if err != nil {
		return api.ServiceAccount{}, err
	}
	if err := resolveNamespace(&sa.Metadata, namespace); err != nil {
		return api.ServiceAccount{}, err
	}
	// its identity is not the request's to change
	sa.Name, sa.UID, sa.CreatedAt = name, old.UID, old.CreatedAt
	if err := validateServiceAccount(sa, s.o.Tokens, origin); err != nil {
		return api.ServiceAccount{}, err
	}
	if err := s.repo.PutNamespaceServiceAccount(namespace, &sa); err != nil {
		return api.ServiceAccount{}, internal(err, origin)
	}
	return toAPI[api.ServiceAccount](sa, origin)
}

func (s *Server) DeleteServiceAccount(ctx context.Context, namespace, name string) error {
	const origin = "rbac.DeleteServiceAccount"
	if err := s.namespace(ctx, namespace, serviceAccounts, "delete"); err != nil {
		return err
	}
	if _, err := s.repo.GetNamespaceServiceAccount(namespace, name); err != nil {
		return notFoundOrInternal(err, origin, "service account %q not found", name)
	}
	if err := s.repo.DeleteNamespaceServiceAccount(namespace, name); err != nil {
		return internal(err, origin)
	}
	return nil
}

// CreateServiceAccountToken is the token action: a token of the service
// account, for its audience (the authorization server's first resource,
// Kayra, when empty), lasting expires_in (the default when empty, at most
// the longest).
func (s *Server) CreateServiceAccountToken(ctx context.Context, namespace, name string, body api.ServiceAccountTokenRequest) (api.ServiceAccountToken, error) {
	const origin = "rbac.ServiceAccountToken"
	tokens := s.o.Tokens
	if err := s.namespace(ctx, namespace, serviceAccounts+"/token", "create"); err != nil {
		return api.ServiceAccountToken{}, err
	}
	if tokens.Issuer == nil {
		return api.ServiceAccountToken{}, liberrors.New(http.StatusNotImplemented, origin, "service account tokens need Kayra's authorization server").
			WithSolution("set oauth2.enabled in Kayra's configuration")
	}
	sa, err := s.repo.GetNamespaceServiceAccount(namespace, name)
	if err != nil {
		return api.ServiceAccountToken{}, notFoundOrInternal(err, origin, "service account %q not found", name)
	}
	ttl := tokens.DefaultTTL
	if body.ExpiresIn != "" {
		if ttl, err = time.ParseDuration(body.ExpiresIn); err != nil || ttl <= 0 {
			return api.ServiceAccountToken{}, liberrors.New(http.StatusBadRequest, origin, "expires_in %q: a duration, like 1h", body.ExpiresIn)
		}
	}
	if ttl > tokens.MaxTTL {
		return api.ServiceAccountToken{}, liberrors.New(http.StatusBadRequest, origin, "expires_in %s: more than the %s a token may last", ttl, tokens.MaxTTL).
			WithSolution("ask for a new token when it expires; a CI gets one from its platform's identity")
	}
	audience := body.Audience
	if len(audience) == 0 {
		audience = tokens.Issuer.Resources()[:1]
	}
	for _, a := range audience {
		if !tokens.Issuer.AllowedResource(a) {
			return api.ServiceAccountToken{}, liberrors.New(http.StatusBadRequest, origin, "audience %q: not one of the resources tokens are issued for (%v)", a, tokens.Issuer.Resources())
		}
	}
	token, expires, err := tokens.Issuer.IssueMachineToken(identity.ServiceAccount(namespace, name), sa.UID, identity.KindServiceAccount, slices.Clone(audience), ttl)
	if err != nil {
		return api.ServiceAccountToken{}, internal(err, origin)
	}
	return api.ServiceAccountToken{Token: token, ExpiresAt: expires}, nil
}

// ServiceAccountContext resolves a service account's token, its claims
// already verified as signed by Kayra's authorization server: the service
// account must exist with the token's uid, so a token of a deleted one,
// even one recreated under the same name, is refused.
func (r *Repository) ServiceAccountContext(subject, uid string) (*middleware.AuthContext, error) {
	namespace, name, ok := identity.ParseServiceAccount(subject)
	if !ok {
		return nil, fmt.Errorf("rbac: %q is no service account", subject)
	}
	sa, err := r.GetNamespaceServiceAccount(namespace, name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("rbac: service account %s/%s does not exist", namespace, name)
	}
	if err != nil {
		return nil, err
	}
	if uid == "" || sa.UID != uid {
		return nil, fmt.Errorf("rbac: the token is of an earlier service account %s/%s", namespace, name)
	}
	return &middleware.AuthContext{
		UserID: subject,
		Kind:   identity.KindServiceAccount,
		Groups: identity.ServiceAccountGroups(namespace),
	}, nil
}
