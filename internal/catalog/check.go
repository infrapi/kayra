package catalog

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/infrapi/kayra/internal/rbac"
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

// CheckApiResource is the /check step after CheckApiSubscription: the
// api's stored OpenAPI spec (see ApiSpec) must serve resource as a
// namespaced resource (404) and verb on it (405), so a request for a
// resource the app doesn't have is answered as that, not as an RBAC
// denial. An active subscription always has a spec (the sync that
// activated it needed one); a missing one is a 503, never a pass.
func (r *Repository) CheckApiResource(api, resource, verb, deploymentPlatform, deploymentRegion string) *liberrors.Error {
	const origin = "catalog.CheckApiResource"

	spec, err := r.GetApiSpec(deploymentPlatform, deploymentRegion, api)
	if err != nil {
		if err == store.ErrNotFound {
			return liberrors.New(http.StatusServiceUnavailable, origin, "no openapi spec stored for api %q, so its resources can't be checked", api).
				WithRetryable(true).
				WithSolution("the spec is fetched from the app at each sync: bump the registration's sync_id, and check the reconciler's logs")
		}
		return liberrors.Wrap(err, http.StatusInternalServerError, origin, "read openapi spec of api %q", api)
	}

	res, found := findResource(spec.Resources, resource, true)
	if !found {
		if _, cluster := findResource(spec.Resources, resource, false); cluster {
			return liberrors.New(http.StatusNotFound, origin, "resource %q of api %q is cluster-scoped: it can't be addressed in a namespace", resource, api)
		}
		lerr := liberrors.New(http.StatusNotFound, origin, "api %q has no resource %q", api, resource)
		if guess := closeResource(spec.Resources, resource); guess != "" {
			return lerr.WithSolution("did you mean %q? List its resources with `kayra-cli apis --api-group %s`", guess, api)
		}
		return lerr.WithSolution("list its resources with `kayra-cli apis --api-group %s`", api)
	}
	if !containsString(res.Verbs, verb) {
		return liberrors.New(http.StatusMethodNotAllowed, origin, "resource %q of api %q doesn't support %q (supported: %s)", resource, api, verb, strings.Join(res.Verbs, ", "))
	}
	return nil
}

func findResource(resources []ApiResource, name string, namespaced bool) (ApiResource, bool) {
	for _, r := range resources {
		if r.Name == name && r.Namespaced == namespaced {
			return r, true
		}
	}
	return ApiResource{}, false
}

// closeResource suggests the namespaced resource name only a trailing
// "s" away from name ("dashboard" -> "dashboards"), the usual mistake.
func closeResource(resources []ApiResource, name string) string {
	for _, cand := range []string{name + "s", strings.TrimSuffix(name, "s")} {
		if cand == name {
			continue
		}
		if _, ok := findResource(resources, cand, true); ok {
			return cand
		}
	}
	return ""
}

// ValidateRoleRules checks a namespace Role's rules against the apis
// they name, before it's saved (see rbac.RegisterNamespaceRoutes):
// every api must be registered here (or be one of Kayra's own, or
// "*"), every resource must be one the api's spec serves as a
// namespaced resource (or "*"), and every verb must be supported by at
// least one of the rule's resources (or be "*"). A registered api with
// no spec yet (never synced) can't be checked, so its resources and
// verbs are accepted as-is.
func (r *Repository) ValidateRoleRules(rules []rbac.Rule, deploymentPlatform, deploymentRegion string) *liberrors.Error {
	const origin = "catalog.ValidateRoleRules"
	builtin := map[string]bool{CatalogAPI: true, SystemAPI: true, rbac.AuthorizationAPI: true}

	for i, rule := range rules {
		for _, api := range rule.Apis {
			if api == "*" || builtin[api] {
				continue
			}
			if _, err := r.GetClusterApiRegistration(deploymentPlatform, deploymentRegion, api); err != nil {
				if err == store.ErrNotFound {
					return liberrors.New(http.StatusBadRequest, origin, "rules[%d]: api %q is not registered", i, api).
						WithSolution("use the api's long name, as `kayra-cli apis` lists it")
				}
				return liberrors.Wrap(err, http.StatusInternalServerError, origin, "read api registration %q", api)
			}
			spec, err := r.GetApiSpec(deploymentPlatform, deploymentRegion, api)
			if err == store.ErrNotFound {
				continue
			}
			if err != nil {
				return liberrors.Wrap(err, http.StatusInternalServerError, origin, "read openapi spec of api %q", api)
			}

			verbs := map[string]bool{}
			for _, name := range rule.Resources {
				if name == "*" {
					for _, res := range spec.Resources {
						if res.Namespaced {
							for _, v := range res.Verbs {
								verbs[v] = true
							}
						}
					}
					continue
				}
				res, ok := findResource(spec.Resources, name, true)
				if !ok {
					lerr := liberrors.New(http.StatusBadRequest, origin, "rules[%d]: api %q has no namespaced resource %q", i, api, name)
					if guess := closeResource(spec.Resources, name); guess != "" {
						return lerr.WithSolution("did you mean %q? List its resources with `kayra-cli apis --api-group %s`", guess, api)
					}
					return lerr.WithSolution("list its resources with `kayra-cli apis --api-group %s`", api)
				}
				for _, v := range res.Verbs {
					verbs[v] = true
				}
			}
			for _, v := range rule.Verbs {
				if v != "*" && !verbs[v] {
					return liberrors.New(http.StatusBadRequest, origin, "rules[%d]: none of resources %s of api %q supports %q", i, strings.Join(rule.Resources, ", "), api, v)
				}
			}
		}
	}
	return nil
}
