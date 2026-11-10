package catalog

import (
	"net/http"
	"regexp"

	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

var (
	dnsLabel     = `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`
	longApiName  = regexp.MustCompile(`^` + dnsLabel + `(\.` + dnsLabel + `)+$`)
	shortApiName = regexp.MustCompile(`^` + dnsLabel + `$`)
)

// IsLongApiName reports whether name is a valid api id: a lowercase DNS
// name of at least two labels, e.g. "compute.example.com".
func IsLongApiName(name string) bool { return longApiName.MatchString(name) }

// IsShortApiName reports whether name is a valid ApiRegistration
// ShortName: a single lowercase DNS label, e.g. "compute".
func IsShortApiName(name string) bool { return shortApiName.MatchString(name) }

// findByShortName returns the registration in platform/region whose
// ShortName is shortName, if any — used to point a caller who passed a
// short name where the long one is required at the right value.
func (r *Repository) findByShortName(platform, region, shortName string) (ApiRegistration, bool, error) {
	if shortName == "" {
		return ApiRegistration{}, false, nil
	}
	regs, err := r.ListClusterApiRegistrations()
	if err != nil {
		return ApiRegistration{}, false, err
	}
	for _, reg := range regs {
		if reg.Platform == platform && reg.Region == region && reg.ShortName == shortName {
			return reg, true, nil
		}
	}
	return ApiRegistration{}, false, nil
}

// CheckNamespace is step 1 of every /check decision (see
// rbac.RegisterAuthorizeRoute for the full order): namespace exists
// (404). Any store failure other than store.ErrNotFound is a 500.
func (r *Repository) CheckNamespace(namespace string) *liberrors.Error {
	const origin = "catalog.CheckNamespace"
	if _, err := r.GetNamespace(namespace); err != nil {
		return notFoundOrInternal(err, origin, "namespace %q not found", namespace)
	}
	return nil
}

// CheckApiSubscription is steps 3–5 of every /check decision, run only
// once the caller is known to be a member of namespace (step 2), so a
// non-member never learns what a namespace is subscribed to:
//
//  3. api (its long name, e.g. "compute.example.com") is an
//     ApiRegistration in this deployment's own
//     deploymentPlatform/deploymentRegion (404),
//  4. namespace is subscribed to it (403),
//  5. that subscription is active (403), whatever the verb: until the
//     initial sync has run (see Repository.ActivateSubscription) nothing
//     is provisioned for namespace, so the api is not ready to use at
//     all. An active subscription stays usable for every verb even when
//     it is behind its registration's SyncID — a v1 api stays backward
//     compatible, so a pending re-sync is the api owner's to plan, never
//     a reason to refuse callers.
//
// Any store failure other than store.ErrNotFound is a 500.
func (r *Repository) CheckApiSubscription(namespace, api, deploymentPlatform, deploymentRegion string) *liberrors.Error {
	const origin = "catalog.CheckApiSubscription"

	if _, err := r.GetClusterApiRegistration(deploymentPlatform, deploymentRegion, api); err != nil {
		lerr := notFoundOrInternal(err, origin, "api %q is not registered in %s/%s", api, deploymentPlatform, deploymentRegion)
		if lerr.Code == http.StatusNotFound {
			if reg, found, ferr := r.findByShortName(deploymentPlatform, deploymentRegion, api); ferr == nil && found {
				lerr = lerr.WithSolution("%q is a short name: use the api's long name %q", api, reg.Name)
			}
		}
		return lerr
	}

	sub, err := r.GetNamespaceSubscription(namespace, api)
	if err != nil {
		if err == store.ErrNotFound {
			return liberrors.New(http.StatusForbidden, origin, "namespace %q is not subscribed to api %q", namespace, api).
				WithSolution("subscribe first: POST /apis/%s/v1/namespaces/%s/subscriptions with {\"api\": %q}", CatalogAPI, namespace, api)
		}
		return liberrors.Wrap(err, http.StatusInternalServerError, origin, "read subscription of namespace %q to api %q", namespace, api)
	}

	if !sub.Active {
		lerr := liberrors.New(http.StatusForbidden, origin, "subscription of namespace %q to api %q is not active yet (state %q): its initial sync has not completed, so the api is not ready", namespace, api, sub.State)
		if sub.State == SubscriptionStateError {
			return lerr.WithSolution("the initial sync failed: ask the owner of api %q to check it, then trigger a re-sync with PUT /apis/%s/v1/namespaces/%s/subscriptions/%s/sync", api, CatalogAPI, namespace, api)
		}
		return lerr.WithRetryable(true).WithSolution("wait for the initial sync to finish, then retry")
	}
	return nil
}
