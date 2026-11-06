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

// CheckSubscribedApi is the precondition every RBAC check against an
// app's API must satisfy before its rules are even consulted, checked
// in this order, each failure returned as its own error:
//
//  1. namespace exists (404),
//  2. api (its long name, e.g. "compute.example.com") is an
//     ApiRegistration in this deployment's own
//     deploymentPlatform/deploymentRegion (404),
//  3. namespace is subscribed to it (403),
//  4. for any verb other than a read (see IsReadVerb), that subscription
//     is active (403): until Reconciler has activated it (see
//     Repository.ActivateSubscription) nothing has been provisioned for
//     namespace yet, so it may only read, never create or change.
//
// Any store failure other than store.ErrNotFound is a 500.
func (r *Repository) CheckSubscribedApi(namespace, api, verb, deploymentPlatform, deploymentRegion string) *liberrors.Error {
	const origin = "catalog.CheckSubscribedApi"

	if _, err := r.GetNamespace(namespace); err != nil {
		return notFoundOrInternal(err, origin, "namespace %q not found", namespace)
	}

	if _, err := r.GetClusterApiRegistration(deploymentPlatform, deploymentRegion, api); err != nil {
		return notFoundOrInternal(err, origin, "api %q not found in %s/%s", api, deploymentPlatform, deploymentRegion)
	}

	sub, err := r.GetNamespaceSubscription(namespace, api)
	if err != nil {
		if err == store.ErrNotFound {
			return liberrors.New(http.StatusForbidden, origin, "namespace %q is not subscribed to api %q", namespace, api)
		}
		return liberrors.Wrap(err, http.StatusInternalServerError, origin, "read subscription of namespace %q to api %q", namespace, api)
	}

	if !sub.Active && !IsReadVerb(verb) {
		return liberrors.New(http.StatusForbidden, origin, "subscription of namespace %q to api %q is not active (state %q): only read verbs (get, list) are allowed until it is reconciled", namespace, api, sub.State)
	}
	return nil
}

// IsReadVerb reports whether verb only reads ("get", "list" — what
// infrapi/lib's pkg/auth derives from GET). Every other verb, including
// any unknown one, counts as a write.
func IsReadVerb(verb string) bool {
	return verb == "get" || verb == "list"
}
