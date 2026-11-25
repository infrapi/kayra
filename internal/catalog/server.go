package catalog

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"

	uuid "github.com/hashicorp/go-uuid"

	"github.com/infrapi/kayra/api"
	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/rbac"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// Server is the catalog API, api/catalog-v1.yaml: the API registrations of
// Kayra's platform and region, decided on the cluster RBAC, and the
// namespaces' subscriptions to them, decided as their other RBAC objects
// (CanManageNamespaceRBAC, on CatalogAPI). Mount it with Register, behind
// the authenticator and httpapi.WithRequest.
type Server struct {
	repo             *Repository
	rbac             *rbac.Repository
	platform, region string
}

var _ Handlers = (*Server)(nil)

// NewServer is the catalog API of repo, its registrations those of
// platform and region, Kayra's own, decided on rbacRepo.
func NewServer(repo *Repository, rbacRepo *rbac.Repository, platform, region string) *Server {
	return &Server{repo: repo, rbac: rbacRepo, platform: platform, region: region}
}

// wire is a stored object as its API type.
func wire[T any](v any, origin string) (T, error) {
	out, err := httpapi.Convert[T](v)
	if err != nil {
		return out, liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
	}
	return out, nil
}

// stored is a request's body as its stored type.
func stored[T any](v any, origin string) (T, error) {
	out, err := httpapi.Convert[T](v)
	if err != nil {
		return out, liberrors.Wrap(err, http.StatusBadRequest, origin, "")
	}
	return out, nil
}

// --- apiregistrations ---

func (s *Server) ListAPIRegistrations(ctx context.Context) ([]api.ApiRegistration, error) {
	const origin = "catalog.ListApiRegistrations"
	if err := s.rbac.AuthorizeClusterRequest(ctx); err != nil {
		return nil, err
	}
	all, err := s.repo.ListClusterApiRegistrations()
	if err != nil {
		return nil, liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
	}
	regs := make([]ApiRegistration, 0, len(all))
	for _, reg := range all {
		if reg.Platform == s.platform && reg.Region == s.region {
			regs = append(regs, reg)
		}
	}
	return wire[[]api.ApiRegistration](regs, origin)
}

// CreateAPIRegistration registers an API, or replaces its registration:
// its platform and region Kayra's, its version v1 when empty, a sync_id
// made when none is sent, its uid kept across replacements.
func (s *Server) CreateAPIRegistration(ctx context.Context, body api.ApiRegistration) (api.ApiRegistration, error) {
	const origin = "catalog.CreateApiRegistration"
	if err := s.rbac.AuthorizeClusterRequest(ctx); err != nil {
		return api.ApiRegistration{}, err
	}
	reg, err := stored[ApiRegistration](body, origin)
	if err != nil {
		return api.ApiRegistration{}, err
	}
	reg.Platform, reg.Region = s.platform, s.region
	reg.Version = reg.APIVersion()
	if reg.SyncID == "" {
		syncID, err := uuid.GenerateUUID()
		if err != nil {
			return api.ApiRegistration{}, liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
		}
		reg.SyncID = syncID
	}
	if err := validateApiRegistration(s.repo, reg); err != nil {
		return api.ApiRegistration{}, err
	}
	// the uid is Kayra's: kept from the registration it replaces, made
	// for a new one, never the request's
	reg.UID = ""
	if existing, err := s.repo.GetClusterApiRegistration(s.platform, s.region, reg.Name); err == nil {
		reg.UID = existing.UID
	}
	if err := ensureUID(&reg); err != nil {
		return api.ApiRegistration{}, liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
	}
	if err := s.repo.PutClusterApiRegistration(&reg); err != nil {
		return api.ApiRegistration{}, liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
	}
	return wire[api.ApiRegistration](reg, origin)
}

func (s *Server) GetAPIRegistration(ctx context.Context, name string) (api.ApiRegistration, error) {
	const origin = "catalog.GetApiRegistration"
	if err := s.rbac.AuthorizeClusterRequest(ctx); err != nil {
		return api.ApiRegistration{}, err
	}
	reg, err := s.repo.GetClusterApiRegistration(s.platform, s.region, name)
	if err != nil {
		return api.ApiRegistration{}, notFoundOrInternal(err, origin, "api registration %q not found", name)
	}
	return wire[api.ApiRegistration](reg, origin)
}

// UpdateAPIRegistration replaces a registration: its name, uid and
// canary_namespaces (its sync action's) stay.
func (s *Server) UpdateAPIRegistration(ctx context.Context, name string, body api.ApiRegistration) (api.ApiRegistration, error) {
	const origin = "catalog.UpdateApiRegistration"
	if err := s.rbac.AuthorizeClusterRequest(ctx); err != nil {
		return api.ApiRegistration{}, err
	}
	existing, err := s.repo.GetClusterApiRegistration(s.platform, s.region, name)
	if err != nil {
		return api.ApiRegistration{}, notFoundOrInternal(err, origin, "api registration %q not found", name)
	}
	reg, err := stored[ApiRegistration](body, origin)
	if err != nil {
		return api.ApiRegistration{}, err
	}
	reg.Platform, reg.Region, reg.Name = s.platform, s.region, name
	reg.Version = reg.APIVersion()
	reg.CanaryNamespaces = existing.CanaryNamespaces
	reg.UID = existing.UID
	if err := ensureUID(&reg); err != nil {
		return api.ApiRegistration{}, liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
	}
	if err := validateApiRegistration(s.repo, reg); err != nil {
		return api.ApiRegistration{}, err
	}
	if err := s.repo.PutClusterApiRegistration(&reg); err != nil {
		return api.ApiRegistration{}, liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
	}
	return wire[api.ApiRegistration](reg, origin)
}

// DeleteAPIRegistration deletes a registration no other registration's
// depends_on and no subscription references.
func (s *Server) DeleteAPIRegistration(ctx context.Context, name string) error {
	const origin = "catalog.DeleteApiRegistration"
	if err := s.rbac.AuthorizeClusterRequest(ctx); err != nil {
		return err
	}
	if _, err := s.repo.GetClusterApiRegistration(s.platform, s.region, name); err != nil {
		return notFoundOrInternal(err, origin, "api registration %q not found", name)
	}
	referenced, err := s.repo.apiRegistrationIsReferenced(s.platform, s.region, name, s.platform, s.region)
	if err != nil {
		return liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
	}
	if referenced {
		return liberrors.New(http.StatusConflict, origin,
			"api registration %q is still referenced by another registration's depends_on or by a subscription", name)
	}
	if err := s.repo.DeleteClusterApiRegistration(s.platform, s.region, name); err != nil {
		return liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
	}
	return nil
}

// GetAPIRegistrationSpec is the contract the reconciler last read from the
// API: any authenticated caller, as discovery.
func (s *Server) GetAPIRegistrationSpec(ctx context.Context, name string) (map[string]any, error) {
	const origin = "catalog.GetApiSpec"
	if _, err := rbac.Caller(ctx, origin); err != nil {
		return nil, err
	}
	if _, err := s.repo.GetClusterApiRegistration(s.platform, s.region, name); err != nil {
		return nil, notFoundOrInternal(err, origin, "api registration %q not found", name)
	}
	spec, err := s.repo.GetApiSpec(s.platform, s.region, name)
	if err != nil {
		lerr := notFoundOrInternal(err, origin, "no openapi spec stored for api %q yet", name)
		if lerr.Code == http.StatusNotFound {
			lerr = lerr.WithSolution("the spec is fetched from the app at its next sync: bump the registration's sync_id, and check the reconciler's logs if it still doesn't appear")
		}
		return nil, lerr
	}
	var doc map[string]any
	if err := json.Unmarshal(spec.Spec, &doc); err != nil {
		return nil, liberrors.Wrap(err, http.StatusInternalServerError, origin, "the stored spec of api %q", name)
	}
	return doc, nil
}

// GetAPIRegistrationStatus is each active subscription to the API, by
// namespace, against its sync_id.
func (s *Server) GetAPIRegistrationStatus(ctx context.Context, name string) (api.ApiRegistrationStatus, error) {
	const origin = "catalog.ApiRegistrationStatus"
	if err := s.rbac.AuthorizeClusterRequest(ctx); err != nil {
		return api.ApiRegistrationStatus{}, err
	}
	reg, err := s.repo.GetClusterApiRegistration(s.platform, s.region, name)
	if err != nil {
		return api.ApiRegistrationStatus{}, notFoundOrInternal(err, origin, "api registration %q not found", name)
	}
	subs, err := s.repo.ListSubscriptionsToApi(name)
	if err != nil {
		return api.ApiRegistrationStatus{}, liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
	}
	resp := apiRegistrationStatusResponse{Name: reg.Name, SyncID: reg.SyncID, Subscriptions: []subscriptionSyncStatus{}}
	for namespace, sub := range subs {
		if !sub.Active {
			continue
		}
		resp.Subscriptions = append(resp.Subscriptions, subscriptionSyncStatus{
			Namespace:     namespace,
			State:         sub.State,
			CurrentSyncID: sub.CurrentSyncID,
			Synced:        sub.CurrentSyncID == reg.SyncID,
		})
	}
	sort.Slice(resp.Subscriptions, func(i, j int) bool {
		return resp.Subscriptions[i].Namespace < resp.Subscriptions[j].Namespace
	})
	return wire[api.ApiRegistrationStatus](resp, origin)
}

// SyncAPIRegistration releases a new sync_id: to canary_namespaces only
// when given; without, an ongoing canary is released to every namespace,
// at its sync_id, and with none ongoing a new sync_id reaches them all.
func (s *Server) SyncAPIRegistration(ctx context.Context, name string, body api.ApiRegistrationSync) (api.ApiRegistration, error) {
	const origin = "catalog.SyncApiRegistration"
	if err := s.rbac.AuthorizeClusterRequest(ctx); err != nil {
		return api.ApiRegistration{}, err
	}
	reg, err := s.repo.GetClusterApiRegistration(s.platform, s.region, name)
	if err != nil {
		return api.ApiRegistration{}, notFoundOrInternal(err, origin, "api registration %q not found", name)
	}
	newSyncID := func() error {
		syncID, err := uuid.GenerateUUID()
		if err != nil {
			return liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
		}
		reg.SyncID = syncID
		return nil
	}
	switch {
	case len(body.CanaryNamespaces) > 0:
		for _, ns := range body.CanaryNamespaces {
			if _, err := s.repo.GetNamespaceSubscription(ns, name); err != nil {
				return api.ApiRegistration{}, notFoundOrInternal(err, origin, "namespace %q is not subscribed to %q", ns, name)
			}
		}
		if err := newSyncID(); err != nil {
			return api.ApiRegistration{}, err
		}
		reg.CanaryNamespaces = body.CanaryNamespaces
	case len(reg.CanaryNamespaces) > 0:
		// the release: the canary's sync_id, to every namespace
		reg.CanaryNamespaces = nil
	default:
		if err := newSyncID(); err != nil {
			return api.ApiRegistration{}, err
		}
	}
	if err := s.repo.PutClusterApiRegistration(&reg); err != nil {
		return api.ApiRegistration{}, liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
	}
	return wire[api.ApiRegistration](reg, origin)
}

// --- subscriptions ---

func (s *Server) subscription(sub Subscription, origin string) (api.Subscription, error) {
	return wire[api.Subscription](buildSubscriptionResponse(s.repo, sub, s.platform, s.region), origin)
}

func (s *Server) ListSubscriptions(ctx context.Context, namespace string) ([]api.Subscription, error) {
	const origin = "catalog.ListSubscriptions"
	if err := s.rbac.AuthorizeNamespaceRBAC(ctx, namespace, CatalogAPI, "subscriptions", "list"); err != nil {
		return nil, err
	}
	subs, err := s.repo.ListNamespaceSubscriptions(namespace)
	if err != nil {
		return nil, liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
	}
	out := make([]subscriptionResponse, len(subs))
	for i, sub := range subs {
		out[i] = buildSubscriptionResponse(s.repo, sub, s.platform, s.region)
	}
	return wire[[]api.Subscription](out, origin)
}

// CreateSubscription subscribes the namespace to an API, inactive until
// its first sync, whatever else the request says.
func (s *Server) CreateSubscription(ctx context.Context, namespace string, body api.Subscription) (api.Subscription, error) {
	const origin = "catalog.CreateSubscription"
	if err := s.rbac.AuthorizeNamespaceRBAC(ctx, namespace, CatalogAPI, "subscriptions", "create"); err != nil {
		return api.Subscription{}, err
	}
	sub := Subscription{ApiName: body.API, Active: false, State: SubscriptionStateInit}
	if err := validateSubscription(s.repo, sub, s.platform, s.region); err != nil {
		return api.Subscription{}, err
	}
	if reg, err := s.repo.GetClusterApiRegistration(s.platform, s.region, sub.ApiName); err == nil {
		if err := reg.Allows(namespace); err != nil {
			return api.Subscription{}, err
		}
	}
	if err := s.repo.PutNamespaceSubscription(namespace, &sub); err != nil {
		return api.Subscription{}, liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
	}
	return s.subscription(sub, origin)
}

func (s *Server) GetSubscription(ctx context.Context, namespace, apiName string) (api.Subscription, error) {
	const origin = "catalog.GetSubscription"
	if err := s.rbac.AuthorizeNamespaceRBAC(ctx, namespace, CatalogAPI, "subscriptions", "get"); err != nil {
		return api.Subscription{}, err
	}
	sub, err := s.repo.GetNamespaceSubscription(namespace, apiName)
	if err != nil {
		return api.Subscription{}, notFoundOrInternal(err, origin, "subscription to %q not found", apiName)
	}
	return s.subscription(sub, origin)
}

func (s *Server) DeleteSubscription(ctx context.Context, namespace, apiName string) error {
	const origin = "catalog.DeleteSubscription"
	if err := s.rbac.AuthorizeNamespaceRBAC(ctx, namespace, CatalogAPI, "subscriptions", "delete"); err != nil {
		return err
	}
	if _, err := s.repo.GetNamespaceSubscription(namespace, apiName); err != nil {
		return notFoundOrInternal(err, origin, "subscription to %q not found", apiName)
	}
	if err := s.repo.DeleteNamespaceSubscription(namespace, apiName); err != nil {
		return liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
	}
	return nil
}

// SyncSubscription clears the subscription's current_sync_id, for the
// reconciler to reconcile it again: its own resource, subscriptions/sync,
// and verb patch, so granting subscriptions does not grant it.
func (s *Server) SyncSubscription(ctx context.Context, namespace, apiName string) (api.Subscription, error) {
	const origin = "catalog.SyncSubscription"
	if err := s.rbac.AuthorizeNamespaceRBAC(ctx, namespace, CatalogAPI, "subscriptions/sync", "patch"); err != nil {
		return api.Subscription{}, err
	}
	sub, err := s.repo.GetNamespaceSubscription(namespace, apiName)
	if err != nil {
		return api.Subscription{}, notFoundOrInternal(err, origin, "subscription to %q not found", apiName)
	}
	if err := s.repo.SetSubscriptionSyncID(namespace, apiName, ""); err != nil {
		return api.Subscription{}, liberrors.Wrap(err, http.StatusInternalServerError, origin, "")
	}
	sub.CurrentSyncID = ""
	return s.subscription(sub, origin)
}
