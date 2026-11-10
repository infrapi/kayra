package rbac

import (
	"github.com/infrapi/kayra/internal/store"
)

// MatchesAny reports whether value is present in list, or list contains
// the wildcard "*".
func MatchesAny(list []string, value string) bool {
	for _, v := range list {
		if v == "*" || v == value {
			return true
		}
	}
	return false
}

// Allows reports whether any rule grants verb on resource for api — the
// rules[] shape: apis/resources/verbs, each wildcardable with "*". api
// is the full API group URN (e.g. "compute.example.com"), never the
// bare app name.
func Allows(rules []Rule, api, resource, verb string) bool {
	for _, r := range rules {
		if MatchesAny(r.Apis, api) && MatchesAny(r.Resources, resource) && MatchesAny(r.Verbs, verb) {
			return true
		}
	}
	return false
}

// AuthorizationAPI is the fixed Rule.Apis value Kayra's own RBAC
// management resources are checked against — named by its API group's
// own URN exactly like any other app's (e.g. "compute.example.com"):
// it gates "groups", "roles", "rolebindings" (CanManageNamespaceRBAC),
// mounted under /apis/authorization.example.com/v1/.... Its sibling for
// subscriptions, catalog.CatalogAPI, lives with the routes it
// gates in internal/catalog. A role that needs both grants a rule per
// api.
//
// "example.com" is a placeholder, not a hardcoded domain: SetAPIDomain
// rebuilds it from a deployment's own domain (config.AppConfig.APIDomain)
// — call it once, before any route is registered or any stored Rule is
// compared against it, since every mount path and every authored
// Role.Rules entry must agree on the same URN.
var AuthorizationAPI = "authorization.example.com"

// SetAPIDomain rebuilds AuthorizationAPI as "authorization.<domain>".
func SetAPIDomain(domain string) {
	AuthorizationAPI = "authorization." + domain
}

// CanManageNamespaceRBAC reports whether a caller identified by userID
// and holding callerGroups (their resolved groups from authn, e.g. the
// "groups" field of /oauth2/userinfo) is granted verb on resource (one
// of "groups", "roles", "rolebindings") for namespace, via Kayra's own
// stored cluster RBAC: either one of callerGroups must be listed in a
// cluster Group's own Groups, or userID must be listed in its Users
// (either list alone is enough), and that Group must be bound by a
// cluster RoleBinding scoped to namespace, to a cluster Role whose
// rules grant api + verb on resource — api is always AuthorizationAPI
// in practice (RequireClusterRBAC's only caller), but is a parameter
// here rather than hardcoded so this stays the one generic check both
// internal/rbac's own namespace routes and internal/catalog's
// Subscription routes share, just against different APIs.
//
// The group half is deliberately matched against the caller's own
// already-resolved groups, not a synced member list: real LDAP
// directories nest groups inside groups (a group's "member" attribute
// listing other group DNs, not user DNs), so a flat member-list sync
// can never contain the calling user no matter how often it's
// refreshed, whereas the groups authn resolved for this caller at login
// time (via memberOf, see internal/authz/ldap.go) already reflect that
// full nested membership — see Group for why this package matches
// against those resolved names directly rather than re-deriving
// directory membership itself. The Users half sidesteps
// group membership altogether, for access that doesn't warrant (or
// can't wait for) a directory group of its own.
//
// Only metadata.namespace is matched: an HTTP request carries no
// region/platform of its own to compare against, and a binding's role and
// groups are already required to share its exact metadata at creation
// time (see validateClusterRoleBinding), so this is not a partial check.
//
// reason explains a false result; it is empty when allowed is true.
func (r *Repository) CanManageNamespaceRBAC(userID string, callerGroups []string, namespace, api, resource, verb string) (allowed bool, reason string, err error) {
	memberGroups, err := r.clusterGroupsMatching(userID, callerGroups)
	if err != nil {
		return false, "", err
	}
	if len(memberGroups) == 0 {
		return false, "neither your user id nor any of your groups match any cluster group's members", nil
	}

	bindings, err := r.ListClusterRoleBindings()
	if err != nil {
		return false, "", err
	}

	var scopedToNamespace, scopedAndMatchedGroup bool
	for _, rb := range bindings {
		if rb.Metadata.Namespace != namespace {
			continue
		}
		scopedToNamespace = true

		if !groupsIntersect(rb.Groups, memberGroups) {
			continue
		}
		scopedAndMatchedGroup = true

		role, err := r.GetClusterRole(rb.Role)
		if err != nil {
			if err == store.ErrNotFound {
				continue
			}
			return false, "", err
		}

		if Allows(role.Rules, api, resource, verb) {
			return true, "", nil
		}
	}

	switch {
	case !scopedToNamespace:
		return false, "no cluster rolebinding is scoped to this namespace", nil
	case !scopedAndMatchedGroup:
		return false, "a cluster rolebinding exists for this namespace, but none of its groups match your groups", nil
	default:
		return false, "your cluster role does not grant this action", nil
	}
}

// clusterGroupsMatching returns the names of every cluster Group with at
// least one configured source matched by userID or callerGroups: a
// match means one of callerGroups is listed in its own Groups, or
// userID is listed in its Users.
func (r *Repository) clusterGroupsMatching(userID string, callerGroups []string) ([]string, error) {
	groups, err := r.ListClusterGroups()
	if err != nil {
		return nil, err
	}

	var names []string
	for _, g := range groups {
		if groupMatchesCaller(g, userID, callerGroups) {
			names = append(names, g.Name)
		}
	}
	return names, nil
}

// Authorize reports whether a caller identified by userID and holding
// callerGroups is granted verb on resource for api, within namespace,
// via that namespace's own Group/Role/RoleBinding objects
// (RegisterNamespaceRoutes' groups/roles/rolebindings CRUD) — the check
// infrapi/lib's auth package calls over HTTP so any app built on top of
// it can authorize a request without storing or evaluating RBAC rules
// itself. api is that app's own full API group URN (e.g.
// "compute.example.com"), matching how it's actually reachable
// (/apis/compute.example.com/v1/...), never the bare app name. Either
// one of callerGroups must be listed in the Groups of one of
// namespace's own Group objects, or userID must be listed in its Users,
// and that Group must be bound by one of namespace's own RoleBindings,
// to a Role whose rules grant api + verb on resource.
//
// This is deliberately a different data set from CanManageNamespaceRBAC's
// cluster-scoped Group/Role/RoleBinding: those bootstrap who may manage a
// namespace's own RBAC objects in the first place; these are the objects
// a namespace's own admins (once CanManageNamespaceRBAC lets them in)
// create to grant everyone else actual access to that namespace's APIs.
//
// reason explains a false result; it is empty when allowed is true.
func (r *Repository) Authorize(userID string, callerGroups []string, namespace, api, resource, verb string) (allowed bool, reason string, err error) {
	memberGroups, err := r.namespaceGroupsMatching(namespace, userID, callerGroups)
	if err != nil {
		return false, "", err
	}
	if len(memberGroups) == 0 {
		return false, "neither your user id nor any of your groups match any group's members in this namespace", nil
	}

	bindings, err := r.ListNamespaceRoleBindings(namespace)
	if err != nil {
		return false, "", err
	}

	var matchedGroup bool
	for _, rb := range bindings {
		if !groupsIntersect(rb.Groups, memberGroups) {
			continue
		}
		matchedGroup = true

		role, err := r.GetNamespaceRole(namespace, rb.Role)
		if err != nil {
			if err == store.ErrNotFound {
				continue
			}
			return false, "", err
		}

		if Allows(role.Rules, api, resource, verb) {
			return true, "", nil
		}
	}

	if !matchedGroup {
		return false, "none of this namespace's rolebindings match your groups", nil
	}
	return false, "your role does not grant this action", nil
}

// namespaceGroupsMatching is clusterGroupsMatching's namespace-scoped
// twin: the names of every namespace Group with at least one configured
// source matched by userID or callerGroups.
func (r *Repository) namespaceGroupsMatching(namespace, userID string, callerGroups []string) ([]string, error) {
	groups, err := r.ListNamespaceGroups(namespace)
	if err != nil {
		return nil, err
	}

	var names []string
	for _, g := range groups {
		if groupMatchesCaller(g, userID, callerGroups) {
			names = append(names, g.Name)
		}
	}
	return names, nil
}

// groupMatchesCaller reports whether g counts the caller as a member:
// one of callerGroups is listed in g.Groups, or userID is listed in
// g.Users (both exact matches, wildcardable with "*" — see MatchesAny).
// Either list, on its own, is enough.
func groupMatchesCaller(g Group, userID string, callerGroups []string) bool {
	for _, cg := range callerGroups {
		if cg != "" && MatchesAny(g.Groups, cg) {
			return true
		}
	}
	return userID != "" && MatchesAny(g.Users, userID)
}

func groupsIntersect(a, b []string) bool {
	set := make(map[string]struct{}, len(b))
	for _, v := range b {
		set[v] = struct{}{}
	}
	for _, v := range a {
		if _, ok := set[v]; ok {
			return true
		}
	}
	return false
}
