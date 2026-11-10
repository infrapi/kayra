// Package rbac stores and serves the cluster- and namespace-scoped
// groups/roles/rolebindings the spec's "Setup cluster group,role,binding"
// and "Create default rights on namespace side" sections describe.
package rbac

// Metadata is the region/platform/namespace scoping carried by every
// group, role and role binding.
type Metadata struct {
	Namespace string `json:"namespace" yaml:"namespace"`
	Region    string `json:"region" yaml:"region"`
	Platform  string `json:"platform" yaml:"platform"`
}

// Group is a named set of external groups and/or directly named users:
// authorization checks a caller's own resolved groups and user id
// directly against these, so there is no separately synced membership
// list. Both are in the already-resolved vocabulary authn/authz
// produces — never raw directory syntax (an LDAP DN, say): Groups
// names real group names exactly as authz.UserInfo resolves them (e.g.
// internal/authz/ldap.go's member_regex extracts "sandbox-sre-sysadmin"
// out of the raw memberOf DN, so that's what goes here, not the DN
// itself), checked against the caller's resolved groups; Users names
// specific people directly by their resolved user id, checked against
// the caller's own resolved user id. Either list alone is enough to
// grant membership — a Group can use one, the other, or both. Each
// entry may be "*" to match anything, same wildcarding Rule's own
// fields use (see MatchesAny).
//
// Deliberately not DNs: a user's effective LDAP group membership
// already accounts for nested groups (a group's own "member" attribute
// lists other group DNs, not user DNs, so it can't be checked directly
// — see groupMatchesCaller) by the time authz resolves it into this
// same vocabulary; re-deriving or re-parsing directory syntax here
// would just duplicate that work and risk disagreeing with it.
//
// Not scoped by authorizations.<name> backend: whichever backend
// actually resolved the caller, their resolved groups/id are checked
// against this same list regardless.
type Group struct {
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description" yaml:"description"`
	Metadata    Metadata `json:"metadata" yaml:"metadata"`
	Groups      []string `json:"groups" yaml:"groups"`
	Users       []string `json:"users" yaml:"users"`
}

// Rule is one RBAC rule: which apis, resources and verbs it grants.
// Apis matches the full API group URN (see Authorize) for any other
// app's own routes — e.g. "compute.example.com", never the bare app
// name "compute" — mirroring how that app is actually reachable
// (/apis/compute.example.com/v1/...). Kayra's own management-plane
// resources are just two fixed API URNs in that same vocabulary —
// rbac.AuthorizationAPI and catalog.CatalogAPI — not a
// separate concept.
type Rule struct {
	Apis      []string `json:"apis" yaml:"apis"`
	Resources []string `json:"resources" yaml:"resources"`
	Verbs     []string `json:"verbs" yaml:"verbs"`
}

// Role is a named set of rules.
type Role struct {
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description" yaml:"description"`
	Metadata    Metadata `json:"metadata" yaml:"metadata"`
	Rules       []Rule   `json:"rules" yaml:"rules"`
}

// RoleBinding grants a Role to a set of Groups, at the same
// region/platform/namespace scope.
type RoleBinding struct {
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description" yaml:"description"`
	Metadata    Metadata `json:"metadata" yaml:"metadata"`
	Role        string   `json:"role" yaml:"role"`
	Groups      []string `json:"groups" yaml:"groups"`
}
