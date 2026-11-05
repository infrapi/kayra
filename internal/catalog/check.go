package catalog

import (
	"net/http"
	"strings"

	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// ApiNameFromURN maps a full API group URN ("compute.<domain>") to the
// ApiRegistration name it designates ("compute"). ok is false when urn
// is not a single label directly under this deployment's own api
// domain (see SetAPIDomain) — no registration could ever match it.
func ApiNameFromURN(urn string) (name string, ok bool) {
	name, found := strings.CutSuffix(urn, "."+apiDomain)
	if !found || name == "" || strings.Contains(name, ".") {
		return "", false
	}
	return name, true
}

// CheckSubscribedApi is the precondition every RBAC check against an
// app's API must satisfy before its rules are even consulted, checked
// in this order, each failure returned as its own error:
//
//  1. namespace exists (404),
//  2. apiURN names an ApiRegistration that exists in this deployment's
//     own deploymentPlatform/deploymentRegion (404),
//  3. namespace is subscribed to that registration (403),
//  4. for any verb other than a read (see IsReadVerb), that subscription
//     is active (403): until Reconciler has activated it (see
//     Repository.ActivateSubscription) nothing has been provisioned for
//     namespace yet, so it may only read, never create or change.
//
// Any store failure other than store.ErrNotFound is a 500.
func (r *Repository) CheckSubscribedApi(namespace, apiURN, verb, deploymentPlatform, deploymentRegion string) *liberrors.Error {
	const origin = "catalog.CheckSubscribedApi"

	if _, err := r.GetNamespace(namespace); err != nil {
		return notFoundOrInternal(err, origin, "namespace %q not found", namespace)
	}

	apiName, ok := ApiNameFromURN(apiURN)
	if !ok {
		return liberrors.New(http.StatusNotFound, origin, "api %q not found: not an api group of domain %q", apiURN, apiDomain)
	}
	if _, err := r.GetClusterApiRegistration(deploymentPlatform, deploymentRegion, apiName); err != nil {
		return notFoundOrInternal(err, origin, "api %q not found in %s/%s", apiURN, deploymentPlatform, deploymentRegion)
	}

	sub, err := r.GetNamespaceSubscription(namespace, apiName)
	if err != nil {
		if err == store.ErrNotFound {
			return liberrors.New(http.StatusForbidden, origin, "namespace %q is not subscribed to api %q", namespace, apiURN)
		}
		return liberrors.Wrap(err, http.StatusInternalServerError, origin, "read subscription of namespace %q to api %q", namespace, apiURN)
	}

	if !sub.Active && !IsReadVerb(verb) {
		return liberrors.New(http.StatusForbidden, origin, "subscription of namespace %q to api %q is not active (state %q): only read verbs (get, list) are allowed until it is reconciled", namespace, apiURN, sub.State)
	}
	return nil
}

// IsReadVerb reports whether verb only reads ("get", "list" — what
// infrapi/lib's pkg/auth derives from GET). Every other verb, including
// any unknown one, counts as a write.
func IsReadVerb(verb string) bool {
	return verb == "get" || verb == "list"
}
