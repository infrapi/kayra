package rbac

import (
	"testing"

	"github.com/infrapi/kayra/internal/store"
)

func newTestRepo(t *testing.T) *Repository {
	t.Helper()
	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return NewRepository(s, store.NewKeys(""))
}

func TestClusterGroupRoundTrip(t *testing.T) {
	repo := newTestRepo(t)

	g := Group{
		Name:        "thetenant-group-sysadmin",
		Description: "default group for sysadmin",
		Metadata:    Metadata{Namespace: "thetenant", Region: "eu-west-1", Platform: "sandbox"},
		Groups:      []string{"sandbox-thetenant-sysadmin"},
	}

	if err := repo.PutClusterGroup(g); err != nil {
		t.Fatalf("PutClusterGroup: %v", err)
	}

	got, err := repo.GetClusterGroup(g.Name)
	if err != nil {
		t.Fatalf("GetClusterGroup: %v", err)
	}
	if got.Name != g.Name || got.Metadata != g.Metadata {
		t.Fatalf("GetClusterGroup = %+v, want %+v", got, g)
	}
}

func TestNamespaceRoleAndBindingRoundTrip(t *testing.T) {
	repo := newTestRepo(t)
	ns := "myns"

	role := Role{
		Name:     "myns-default-role-ro",
		Metadata: Metadata{Namespace: ns, Region: "eu-west-1", Platform: "sandbox"},
		Rules:    []Rule{{Apis: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"get", "list"}}},
	}
	if err := repo.PutNamespaceRole(ns, role); err != nil {
		t.Fatalf("PutNamespaceRole: %v", err)
	}

	rb := RoleBinding{
		Name:     "myns-default-binding-ro",
		Metadata: role.Metadata,
		Role:     role.Name,
		Groups:   []string{"myns-group-apps"},
	}
	if err := repo.PutNamespaceRoleBinding(ns, rb); err != nil {
		t.Fatalf("PutNamespaceRoleBinding: %v", err)
	}

	gotRole, err := repo.GetNamespaceRole(ns, role.Name)
	if err != nil {
		t.Fatalf("GetNamespaceRole: %v", err)
	}
	if len(gotRole.Rules) != 1 {
		t.Fatalf("GetNamespaceRole rules = %+v", gotRole.Rules)
	}

	gotBinding, err := repo.GetNamespaceRoleBinding(ns, rb.Name)
	if err != nil {
		t.Fatalf("GetNamespaceRoleBinding: %v", err)
	}
	if gotBinding.Role != role.Name {
		t.Fatalf("GetNamespaceRoleBinding.Role = %q, want %q", gotBinding.Role, role.Name)
	}
}

func TestClusterGroupListAndDelete(t *testing.T) {
	repo := newTestRepo(t)

	for _, name := range []string{"g-b", "g-a"} {
		if err := repo.PutClusterGroup(Group{Name: name}); err != nil {
			t.Fatalf("PutClusterGroup(%s): %v", name, err)
		}
	}

	groups, err := repo.ListClusterGroups()
	if err != nil {
		t.Fatalf("ListClusterGroups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("ListClusterGroups = %v, want 2 entries", groups)
	}

	if err := repo.DeleteClusterGroup("g-a"); err != nil {
		t.Fatalf("DeleteClusterGroup: %v", err)
	}
	if _, err := repo.GetClusterGroup("g-a"); err != store.ErrNotFound {
		t.Fatalf("GetClusterGroup after delete = %v, want ErrNotFound", err)
	}

	groups, err = repo.ListClusterGroups()
	if err != nil {
		t.Fatalf("ListClusterGroups after delete: %v", err)
	}
	if len(groups) != 1 || groups[0].Name != "g-b" {
		t.Fatalf("ListClusterGroups after delete = %v, want [g-b]", groups)
	}
}

func TestClusterRoleAndRoleBindingListAndDelete(t *testing.T) {
	repo := newTestRepo(t)

	if err := repo.PutClusterRole(Role{Name: "r1"}); err != nil {
		t.Fatalf("PutClusterRole: %v", err)
	}
	if err := repo.PutClusterRoleBinding(RoleBinding{Name: "b1", Role: "r1"}); err != nil {
		t.Fatalf("PutClusterRoleBinding: %v", err)
	}

	roles, err := repo.ListClusterRoles()
	if err != nil || len(roles) != 1 {
		t.Fatalf("ListClusterRoles = %v, %v", roles, err)
	}
	bindings, err := repo.ListClusterRoleBindings()
	if err != nil || len(bindings) != 1 {
		t.Fatalf("ListClusterRoleBindings = %v, %v", bindings, err)
	}

	if err := repo.DeleteClusterRole("r1"); err != nil {
		t.Fatalf("DeleteClusterRole: %v", err)
	}
	if _, err := repo.GetClusterRole("r1"); err != store.ErrNotFound {
		t.Fatalf("GetClusterRole after delete = %v, want ErrNotFound", err)
	}

	if err := repo.DeleteClusterRoleBinding("b1"); err != nil {
		t.Fatalf("DeleteClusterRoleBinding: %v", err)
	}
	if _, err := repo.GetClusterRoleBinding("b1"); err != store.ErrNotFound {
		t.Fatalf("GetClusterRoleBinding after delete = %v, want ErrNotFound", err)
	}
}

func TestNamespaceListAndDelete(t *testing.T) {
	repo := newTestRepo(t)
	ns := "myns"
	other := "otherns"

	if err := repo.PutNamespaceGroup(ns, Group{Name: "g1"}); err != nil {
		t.Fatalf("PutNamespaceGroup: %v", err)
	}
	if err := repo.PutNamespaceGroup(other, Group{Name: "g1"}); err != nil {
		t.Fatalf("PutNamespaceGroup(other): %v", err)
	}

	groups, err := repo.ListNamespaceGroups(ns)
	if err != nil {
		t.Fatalf("ListNamespaceGroups: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("ListNamespaceGroups(%s) = %v, want 1 entry (must not leak other namespaces)", ns, groups)
	}

	if err := repo.DeleteNamespaceGroup(ns, "g1"); err != nil {
		t.Fatalf("DeleteNamespaceGroup: %v", err)
	}
	if _, err := repo.GetNamespaceGroup(ns, "g1"); err != store.ErrNotFound {
		t.Fatalf("GetNamespaceGroup after delete = %v, want ErrNotFound", err)
	}
	// the other namespace's identically-named group must survive.
	if _, err := repo.GetNamespaceGroup(other, "g1"); err != nil {
		t.Fatalf("GetNamespaceGroup(other) should be untouched: %v", err)
	}
}
