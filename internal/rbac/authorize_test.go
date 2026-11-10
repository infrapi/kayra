package rbac

import "testing"

func TestMatchesAny(t *testing.T) {
	if !MatchesAny([]string{"*"}, "anything") {
		t.Fatalf("MatchesAny: wildcard should match anything")
	}
	if !MatchesAny([]string{"get", "list"}, "get") {
		t.Fatalf("MatchesAny: exact match should succeed")
	}
	if MatchesAny([]string{"get", "list"}, "delete") {
		t.Fatalf("MatchesAny: should not match an absent value")
	}
	if MatchesAny(nil, "anything") {
		t.Fatalf("MatchesAny: empty list should match nothing")
	}
}

func TestAllows(t *testing.T) {
	rules := []Rule{
		{Apis: []string{"compute.example.com"}, Resources: []string{"*"}, Verbs: []string{"*"}},
	}
	if !Allows(rules, "compute.example.com", "groups", "create") {
		t.Fatalf("Allows: wildcard resource/verb should grant")
	}
	if Allows(rules, "storage.example.com", "groups", "create") {
		t.Fatalf("Allows: wrong service should not grant")
	}

	readOnly := []Rule{
		{Apis: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"get", "list"}},
	}
	if Allows(readOnly, "compute.example.com", "groups", "create") {
		t.Fatalf("Allows: read-only rules should not grant create")
	}
	if !Allows(readOnly, "compute.example.com", "groups", "get") {
		t.Fatalf("Allows: read-only rules should grant get")
	}
}

// seedNamespaceRBAC writes the namespace group/role/rolebinding that
// grants anyone resolved with callerGroup rights to verb on resource for
// api, within namespace — what a namespace's own admins create via
// RegisterNamespaceRoutes once CanManageNamespaceRBAC lets them in.
// Authorize's match against the caller's resolved groups succeeds
// without any membership sync.
func seedNamespaceRBAC(t *testing.T, repo *Repository, callerGroup, namespace, api, resource, verb string) {
	t.Helper()

	groupName := namespace + "-group-user"
	roleName := namespace + "-role-user"
	bindingName := namespace + "-binding-user"
	meta := Metadata{Namespace: namespace}

	if err := repo.PutNamespaceGroup(namespace, &Group{
		Name: groupName, Metadata: meta,
		Groups: []string{callerGroup},
	}); err != nil {
		t.Fatalf("seedNamespaceRBAC PutNamespaceGroup: %v", err)
	}
	if err := repo.PutNamespaceRole(namespace, &Role{
		Name: roleName, Metadata: meta,
		Rules: []Rule{{Apis: []string{api}, Resources: []string{resource}, Verbs: []string{verb}}},
	}); err != nil {
		t.Fatalf("seedNamespaceRBAC PutNamespaceRole: %v", err)
	}
	if err := repo.PutNamespaceRoleBinding(namespace, &RoleBinding{
		Name: bindingName, Metadata: meta, Role: roleName, Groups: []string{groupName},
	}); err != nil {
		t.Fatalf("seedNamespaceRBAC PutNamespaceRoleBinding: %v", err)
	}
}

func TestAuthorizeRequiresMatchingGroupRoleAPIResourceAndVerb(t *testing.T) {
	repo := newTestRepo(t)
	callerGroups := []string{"sandbox-core-rw"}

	// no setup at all: nobody is authorized for anything.
	allowed, reason, err := repo.Authorize("", callerGroups, "core", "compute.example.com", "vm", "list")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if allowed {
		t.Fatalf("Authorize: should deny with no namespace RBAC at all")
	}
	if reason == "" {
		t.Fatalf("Authorize: denial should carry a reason")
	}

	seedNamespaceRBAC(t, repo, "sandbox-core-rw", "core", "compute.example.com", "vm", "list")

	allowed, _, err = repo.Authorize("", callerGroups, "core", "compute.example.com", "vm", "list")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !allowed {
		t.Fatalf("Authorize: should allow once the caller's own group matches the namespace group's LDAP source")
	}

	// same everything, wrong verb: must not leak beyond what the rule grants.
	allowed, _, err = repo.Authorize("", callerGroups, "core", "compute.example.com", "vm", "delete")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if allowed {
		t.Fatalf("Authorize: should not allow a verb the rule doesn't grant")
	}

	// same groups, different namespace: must not leak across namespaces.
	allowed, _, err = repo.Authorize("", callerGroups, "othertenant", "compute.example.com", "vm", "list")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if allowed {
		t.Fatalf("Authorize: should not allow for an unrelated namespace")
	}

	// different groups, same namespace: must not leak across callers.
	allowed, _, err = repo.Authorize("", []string{"some-other-group"}, "core", "compute.example.com", "vm", "list")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if allowed {
		t.Fatalf("Authorize: should not allow a caller whose groups don't match")
	}
}

func TestCanManageNamespaceRBACRequiresMatchingGroupRoleAndNamespace(t *testing.T) {
	repo := newTestRepo(t)
	callerGroups := []string{"sandbox-thetenant-sysadmin"}

	// no setup at all: nobody is authorized for anything.
	allowed, reason, err := repo.CanManageNamespaceRBAC("", callerGroups, "thetenant", AuthorizationAPI, "groups", "create")
	if err != nil {
		t.Fatalf("CanManageNamespaceRBAC: %v", err)
	}
	if allowed {
		t.Fatalf("CanManageNamespaceRBAC: should deny with no cluster RBAC at all")
	}
	if reason == "" {
		t.Fatalf("CanManageNamespaceRBAC: denial should carry a reason")
	}

	seedClusterRBAC(t, repo, "sandbox-thetenant-sysadmin", "thetenant")

	allowed, _, err = repo.CanManageNamespaceRBAC("", callerGroups, "thetenant", AuthorizationAPI, "groups", "create")
	if err != nil {
		t.Fatalf("CanManageNamespaceRBAC: %v", err)
	}
	if !allowed {
		t.Fatalf("CanManageNamespaceRBAC: should allow once the caller's own group matches the cluster group's LDAP source")
	}

	// same groups, different namespace: must not leak across namespaces.
	allowed, _, err = repo.CanManageNamespaceRBAC("", callerGroups, "othertenant", AuthorizationAPI, "groups", "create")
	if err != nil {
		t.Fatalf("CanManageNamespaceRBAC: %v", err)
	}
	if allowed {
		t.Fatalf("CanManageNamespaceRBAC: should not allow for an unrelated namespace")
	}

	// different groups, same namespace: must not leak across callers.
	allowed, _, err = repo.CanManageNamespaceRBAC("", []string{"some-other-group"}, "thetenant", AuthorizationAPI, "groups", "create")
	if err != nil {
		t.Fatalf("CanManageNamespaceRBAC: %v", err)
	}
	if allowed {
		t.Fatalf("CanManageNamespaceRBAC: should not allow a caller whose groups don't match")
	}
}

// TestCanManageNamespaceRBACAllowsDirectUserSource confirms a cluster
// Group's Users can name one specific person directly (by resolved
// user id, rather than a group name) and grant them access by exact
// user id alone — no LDAP group involved at all.
func TestCanManageNamespaceRBACAllowsDirectUserSource(t *testing.T) {
	repo := newTestRepo(t)

	if err := repo.PutClusterGroup(&Group{
		Name:     "thetenant-group-oneoff",
		Metadata: Metadata{Namespace: "thetenant"},
		Users:    []string{"jdoe"},
	}); err != nil {
		t.Fatalf("PutClusterGroup: %v", err)
	}
	if err := repo.PutClusterRole(&Role{
		Name: "thetenant-role-oneoff", Metadata: Metadata{Namespace: "thetenant"},
		Rules: []Rule{{Apis: []string{AuthorizationAPI}, Resources: []string{"groups"}, Verbs: []string{"create"}}},
	}); err != nil {
		t.Fatalf("PutClusterRole: %v", err)
	}
	if err := repo.PutClusterRoleBinding(&RoleBinding{
		Name: "thetenant-binding-oneoff", Metadata: Metadata{Namespace: "thetenant"},
		Role: "thetenant-role-oneoff", Groups: []string{"thetenant-group-oneoff"},
	}); err != nil {
		t.Fatalf("PutClusterRoleBinding: %v", err)
	}

	// the exact named user, no groups at all: allowed.
	allowed, _, err := repo.CanManageNamespaceRBAC("jdoe", nil, "thetenant", AuthorizationAPI, "groups", "create")
	if err != nil {
		t.Fatalf("CanManageNamespaceRBAC: %v", err)
	}
	if !allowed {
		t.Fatalf("CanManageNamespaceRBAC: should allow a user id matching a direct user source")
	}

	// a different user, even carrying unrelated groups: denied.
	allowed, reason, err := repo.CanManageNamespaceRBAC("someone-else", []string{"unrelated-group"}, "thetenant", AuthorizationAPI, "groups", "create")
	if err != nil {
		t.Fatalf("CanManageNamespaceRBAC: %v", err)
	}
	if allowed {
		t.Fatalf("CanManageNamespaceRBAC: should not allow a user id that doesn't match")
	}
	if reason == "" {
		t.Fatalf("CanManageNamespaceRBAC: denial should carry a reason")
	}
}

// TestAuthorizeAllowsDirectUserSource is
// TestCanManageNamespaceRBACAllowsDirectUserSource's namespace-scoped
// twin: a namespace Group naming one person directly grants access by
// exact user id alone.
func TestAuthorizeAllowsDirectUserSource(t *testing.T) {
	repo := newTestRepo(t)

	if err := repo.PutNamespaceGroup("core", &Group{
		Name:     "core-group-oneoff",
		Metadata: Metadata{Namespace: "core"},
		Users:    []string{"jdoe"},
	}); err != nil {
		t.Fatalf("PutNamespaceGroup: %v", err)
	}
	if err := repo.PutNamespaceRole("core", &Role{
		Name: "core-role-oneoff", Metadata: Metadata{Namespace: "core"},
		Rules: []Rule{{Apis: []string{"compute.example.com"}, Resources: []string{"vm"}, Verbs: []string{"list"}}},
	}); err != nil {
		t.Fatalf("PutNamespaceRole: %v", err)
	}
	if err := repo.PutNamespaceRoleBinding("core", &RoleBinding{
		Name: "core-binding-oneoff", Metadata: Metadata{Namespace: "core"},
		Role: "core-role-oneoff", Groups: []string{"core-group-oneoff"},
	}); err != nil {
		t.Fatalf("PutNamespaceRoleBinding: %v", err)
	}

	allowed, _, err := repo.Authorize("jdoe", nil, "core", "compute.example.com", "vm", "list")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !allowed {
		t.Fatalf("Authorize: should allow a user id matching a direct user source")
	}

	allowed, reason, err := repo.Authorize("someone-else", nil, "core", "compute.example.com", "vm", "list")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if allowed {
		t.Fatalf("Authorize: should not allow a user id that doesn't match")
	}
	if reason == "" {
		t.Fatalf("Authorize: denial should carry a reason")
	}
}

// TestCanManageNamespaceRBACHandlesNestedLDAPGroups reproduces the real
// failure report: an LDAP group's "member" attribute can list other group
// DNs (nested groups), not user DNs — so a synced flat member list would
// never contain the calling user no matter how often it's refreshed.
// Checking the caller's own resolved groups against the cluster group's
// configured LDAP source sidesteps that entirely.
func TestCanManageNamespaceRBACHandlesNestedLDAPGroups(t *testing.T) {
	repo := newTestRepo(t)

	if err := repo.PutClusterGroup(&Group{
		Name:     "core-group-sysadmin",
		Metadata: Metadata{Namespace: "core"},
		Groups:   []string{"sandbox-core-sysadmin"},
	}); err != nil {
		t.Fatalf("PutClusterGroup: %v", err)
	}
	// the LDAP group's own "member" attribute would list nested sub-groups,
	// never the calling user directly — exactly what was reported. There is
	// no synced member list to even consult any more: authorization checks
	// the caller's own resolved groups below instead.
	if err := repo.PutClusterRole(&Role{
		Name: "core-role-sysadmin", Metadata: Metadata{Namespace: "core"},
		Rules: []Rule{{Apis: []string{AuthorizationAPI}, Resources: []string{"*"}, Verbs: []string{"*"}}},
	}); err != nil {
		t.Fatalf("PutClusterRole: %v", err)
	}
	if err := repo.PutClusterRoleBinding(&RoleBinding{
		Name: "core-binding-sysadmin", Metadata: Metadata{Namespace: "core"},
		Role: "core-role-sysadmin", Groups: []string{"core-group-sysadmin"},
	}); err != nil {
		t.Fatalf("PutClusterRoleBinding: %v", err)
	}

	// ahdemir's resolved groups, exactly as /oauth2/userinfo reported.
	callerGroups := []string{"sandbox-infra-sysadmin", "sandbox-core-sysadmin", "sandbox-global-sysadmin"}

	allowed, reason, err := repo.CanManageNamespaceRBAC("", callerGroups, "core", AuthorizationAPI, "groups", "create")
	if err != nil {
		t.Fatalf("CanManageNamespaceRBAC: %v", err)
	}
	if !allowed {
		t.Fatalf("CanManageNamespaceRBAC: should allow — reason: %s", reason)
	}
}
