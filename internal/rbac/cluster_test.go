package rbac

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	liberrors "github.com/infrapi/lib/pkg/errors"
)

const (
	computeAPI    = "compute.infrapi.io"
	platformGroup = "sandbox-compute-platform" // the platform's Terraform
)

// seedGlobal writes a global cluster group of callerGroup, bound to a
// global cluster role of rules.
func seedGlobal(t *testing.T, repo *Repository, name, callerGroup string, rules ...Rule) {
	t.Helper()
	if err := repo.PutClusterGroup(&Group{Name: name, Groups: []string{callerGroup}}); err != nil {
		t.Fatal(err)
	}
	if err := repo.PutClusterRole(&Role{Name: name, Rules: rules}); err != nil {
		t.Fatal(err)
	}
	if err := repo.PutClusterRoleBinding(&RoleBinding{Name: name, Role: name, Groups: []string{name}}); err != nil {
		t.Fatal(err)
	}
}

// The built-in sysadmin binding grants every cluster-scoped resource, and
// nothing in a namespace; a global binding grants its role's cluster
// resources only; a binding scoped to a namespace grants nothing
// cluster-scoped.
func TestAuthorizeCluster(t *testing.T) {
	repo := newTestRepo(t)
	repo.SetSysadmin([]string{testSysadminGroup})
	seedClusterRBAC(t, repo, testAdminGroup, testNamespace) // a namespace's admins, scoped to myns
	seedGlobal(t, repo, "compute-platform", platformGroup,
		Rule{Apis: []string{computeAPI}, Resources: []string{"flavors", "hosts"}, Verbs: []string{"*"}})

	for _, c := range []struct {
		groups              []string
		api, resource, verb string
		want                bool
	}{
		{[]string{testSysadminGroup}, computeAPI, "hosts", "create", true},
		{[]string{testSysadminGroup}, AuthorizationAPI, "clusterroles", "escalate", true},
		{[]string{platformGroup}, computeAPI, "hosts", "delete", true},
		{[]string{platformGroup}, computeAPI, "artifacts", "get", false},
		{[]string{platformGroup}, AuthorizationAPI, "clustergroups", "create", false},
		{[]string{testAdminGroup}, AuthorizationAPI, "roles", "create", false}, // scoped to myns only
		{[]string{"nobody"}, computeAPI, "hosts", "get", false},
	} {
		got, reason, err := repo.AuthorizeCluster("u", c.groups, c.api, c.resource, c.verb)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("%v %s %s %s: %v (%s), want %v", c.groups, c.api, c.resource, c.verb, got, reason, c.want)
		}
	}

	// the sysadmin binding grants nothing in a namespace, a global binding
	// neither
	for _, groups := range [][]string{{testSysadminGroup}, {platformGroup}} {
		if ok, _, _ := repo.CanManageNamespaceRBAC("u", groups, testNamespace, AuthorizationAPI, "roles", "create"); ok {
			t.Errorf("%v manages %s", groups, testNamespace)
		}
	}
	if ok, _, _ := repo.CanManageNamespaceRBAC("u", []string{testAdminGroup}, testNamespace, AuthorizationAPI, "roles", "create"); !ok {
		t.Error("the tenant's admins no longer manage it")
	}
}

func TestClusterRequest(t *testing.T) {
	for _, c := range []struct{ method, path, api, resource, verb string }{
		{"POST", "/apis/system.infrapi.io/v1/namespaces", "system.infrapi.io", "namespaces", "create"},
		{"GET", "/apis/system.infrapi.io/v1/namespaces/core", "system.infrapi.io", "namespaces", "get"},
		{"PUT", "/apis/catalog.infrapi.io/v1/apiregistrations/compute.infrapi.io/sync", "catalog.infrapi.io", "apiregistrations/sync", "update"},
		{"GET", "/apis/catalog.infrapi.io/v1/apiregistrations/compute.infrapi.io/status", "catalog.infrapi.io", "apiregistrations/status", "list"},
		{"DELETE", "/apis/authorization.infrapi.io/v1/clusterroles/r", "authorization.infrapi.io", "clusterroles", "delete"},
	} {
		api, resource, verb, err := ClusterRequest(c.path, c.method)
		if err != nil || api != c.api || resource != c.resource || verb != c.verb {
			t.Errorf("%s %s: %s %s %s %v", c.method, c.path, api, resource, verb, err)
		}
	}
	if _, _, _, err := ClusterRequest("/apis/x.infrapi.io/v1", "GET"); err == nil {
		t.Error("no resource")
	}
}

// The cluster routes are behind RequireCluster: a caller without a
// global binding is refused, one with it is let in for what it grants.
func TestRequireCluster(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := newTestRepo(t)
	repo.SetSysadmin([]string{testSysadminGroup})
	seedGlobal(t, repo, "group-admins", "sandbox-iam",
		Rule{Apis: []string{AuthorizationAPI}, Resources: []string{"clustergroups"}, Verbs: []string{"*"}})
	engine := gin.New()
	for name, groups := range map[string][]string{"nobody": {"nobody"}, "iam": {"sandbox-iam"}} {
		g := engine.Group("/"+name, fakeAuthGate(name, groups...))
		g.Any("/apis/*rest", func(c *gin.Context) {
			c.Request.URL.Path = "/apis" + c.Param("rest")
			RequireCluster(repo)(c)
			if !c.IsAborted() {
				c.Status(http.StatusOK)
			}
		})
	}
	for _, c := range []struct {
		who, method, path string
		status            int
	}{
		{"nobody", "POST", "/apis/authorization.infrapi.io/v1/clustergroups", 403},
		{"iam", "POST", "/apis/authorization.infrapi.io/v1/clustergroups", 200},
		{"iam", "POST", "/apis/authorization.infrapi.io/v1/clusterroles", 403},
		{"iam", "POST", "/apis/system.infrapi.io/v1/namespaces", 403},
	} {
		if w := doJSON(t, engine, c.method, "/"+c.who+c.path, nil); w.Code != c.status {
			t.Errorf("%s %s %s: %d %s, want %d", c.who, c.method, c.path, w.Code, w.Body.String(), c.status)
		}
	}
}

// Anti-escalation, on the cluster: a delegated cluster admin writes roles
// and bindings granting what they hold, not more, unless they hold
// escalate or bind.
func TestClusterEscalation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := newTestRepo(t)
	repo.SetSysadmin([]string{testSysadminGroup})
	delegated := []Rule{
		{Apis: []string{AuthorizationAPI}, Resources: []string{"clusterroles", "clusterrolebindings", "clustergroups"}, Verbs: []string{"create", "update", "get", "list"}},
		{Apis: []string{computeAPI}, Resources: []string{"hosts"}, Verbs: []string{"get", "list", "update"}},
	}
	seedGlobal(t, repo, "rbac-delegates", "sandbox-delegates", delegated...)
	engine := gin.New()
	RegisterClusterRoutes(engine.Group("", fakeAuthGate("d", "sandbox-delegates")), repo, noopGate, nil)

	// a subset of what they hold: accepted
	w := doJSON(t, engine, http.MethodPost, "/apis/authorization.infrapi.io/v1/clusterroles", Role{
		Name: "agents", Rules: []Rule{{Apis: []string{computeAPI}, Resources: []string{"hosts"}, Verbs: []string{"update"}}},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("a subset: %d %s", w.Code, w.Body.String())
	}
	// more: refused, naming what
	w = doJSON(t, engine, http.MethodPost, "/apis/authorization.infrapi.io/v1/clusterroles", Role{
		Name: "more", Rules: []Rule{{Apis: []string{computeAPI}, Resources: []string{"hosts"}, Verbs: []string{"delete"}}},
	})
	var problem struct{ Detail string }
	_ = json.Unmarshal(w.Body.Bytes(), &problem)
	if w.Code != http.StatusForbidden || problem.Detail != "it grants compute.infrapi.io hosts delete, which you do not hold" {
		t.Fatalf("more: %d %s", w.Code, w.Body.String())
	}
	// a "*" is covered by a "*" only
	w = doJSON(t, engine, http.MethodPost, "/apis/authorization.infrapi.io/v1/clusterroles", Role{
		Name: "star", Rules: []Rule{{Apis: []string{computeAPI}, Resources: []string{"*"}, Verbs: []string{"get"}}},
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("a star: %d %s", w.Code, w.Body.String())
	}

	// binding a role granting more than they hold: refused
	if err := repo.PutClusterRole(&Role{Name: "root", Rules: []Rule{all}}); err != nil {
		t.Fatal(err)
	}
	if err := repo.PutClusterGroup(&Group{Name: "mine", Groups: []string{"sandbox-delegates"}}); err != nil {
		t.Fatal(err)
	}
	w = doJSON(t, engine, http.MethodPost, "/apis/authorization.infrapi.io/v1/clusterrolebindings", RoleBinding{
		Name: "grab", Role: "root", Groups: []string{"mine"},
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("binding root: %d %s", w.Code, w.Body.String())
	}
	w = doJSON(t, engine, http.MethodPost, "/apis/authorization.infrapi.io/v1/clusterrolebindings", RoleBinding{
		Name: "agents", Role: "agents", Groups: []string{"mine"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("binding a subset: %d %s", w.Code, w.Body.String())
	}

	// with bind, they bind what they do not hold
	seedGlobal(t, repo, "binders", "sandbox-delegates",
		Rule{Apis: []string{AuthorizationAPI}, Resources: []string{"clusterrolebindings"}, Verbs: []string{"bind"}})
	w = doJSON(t, engine, http.MethodPost, "/apis/authorization.infrapi.io/v1/clusterrolebindings", RoleBinding{
		Name: "grab", Role: "root", Groups: []string{"mine"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("binding root, with bind: %d %s", w.Code, w.Body.String())
	}
}

// Anti-escalation, in a namespace: someone delegated roles in a namespace
// writes roles granting what they hold there, not more.
func TestNamespaceEscalation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := newTestRepo(t)
	meta := Metadata{Namespace: testNamespace}
	if err := repo.PutClusterGroup(&Group{Name: "writers", Metadata: meta, Groups: []string{"sandbox-writers"}}); err != nil {
		t.Fatal(err)
	}
	if err := repo.PutClusterRole(&Role{Name: "writers", Metadata: meta, Rules: []Rule{
		{Apis: []string{AuthorizationAPI}, Resources: []string{"roles", "groups", "rolebindings"}, Verbs: []string{"create", "update", "get", "list"}},
		{Apis: []string{computeAPI}, Resources: []string{"vms"}, Verbs: []string{"get", "list"}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := repo.PutClusterRoleBinding(&RoleBinding{Name: "writers", Metadata: meta, Role: "writers", Groups: []string{"writers"}}); err != nil {
		t.Fatal(err)
	}
	engine := gin.New()
	RegisterNamespaceRoutes(engine, repo, fakeAuthGate("w", "sandbox-writers"), nil)
	path := "/apis/authorization.infrapi.io/v1/namespaces/" + testNamespace + "/roles"

	if w := doJSON(t, engine, http.MethodPost, path, Role{Name: "read", Rules: []Rule{
		{Apis: []string{computeAPI}, Resources: []string{"vms"}, Verbs: []string{"get"}},
	}}); w.Code != http.StatusCreated {
		t.Fatalf("a subset: %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, engine, http.MethodPost, path, Role{Name: "all", Rules: []Rule{
		{Apis: []string{computeAPI}, Resources: []string{"*"}, Verbs: []string{"*"}},
	}}); w.Code != http.StatusForbidden {
		t.Fatalf("compute *: %d %s", w.Code, w.Body.String())
	}

	// a namespace's admins (authorization *, so escalate): unaffected
	seedClusterRBAC(t, repo, testAdminGroup, testNamespace)
	admins := gin.New()
	RegisterNamespaceRoutes(admins, repo, fakeAuthGate(testAdmin, testAdminGroup), nil)
	if w := doJSON(t, admins, http.MethodPost, path, Role{Name: "all", Rules: []Rule{
		{Apis: []string{computeAPI}, Resources: []string{"*"}, Verbs: []string{"*"}},
	}}); w.Code != http.StatusCreated {
		t.Fatalf("the admins: %d %s", w.Code, w.Body.String())
	}
}

// /check: a cluster-scoped request decided on the cluster RBAC; Kayra's
// own apis in a namespace as their routes decide them.
func TestCheckCluster(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := newTestRepo(t)
	repo.SetSysadmin([]string{testSysadminGroup})
	seedClusterRBAC(t, repo, testAdminGroup, testNamespace)
	seedGlobal(t, repo, "compute-platform", platformGroup,
		Rule{Apis: []string{computeAPI}, Resources: []string{"hosts"}, Verbs: []string{"*"}})
	var asked []string
	prechecks := Prechecks{
		ClusterResource: func(api, resource, verb string) *liberrors.Error {
			asked = append(asked, api+" "+resource)
			return nil
		},
		Builtin: func(api string) bool { return api == AuthorizationAPI },
	}
	check := func(groups []string, req AuthorizeRequest) AuthorizeResponse {
		t.Helper()
		engine := gin.New()
		RegisterAuthorizeRoute(engine, repo, fakeAuthGate("u", groups...), prechecks, nil)
		w := doJSON(t, engine, http.MethodPost, "/apis/authorization.infrapi.io/v1/check", req)
		if w.Code != http.StatusOK {
			t.Fatalf("%+v: %d %s", req, w.Code, w.Body.String())
		}
		var r AuthorizeResponse
		_ = json.Unmarshal(w.Body.Bytes(), &r)
		return r
	}
	if r := check([]string{platformGroup}, AuthorizeRequest{Api: computeAPI, Resource: "hosts", Verb: "update"}); !r.Allowed {
		t.Errorf("the platform on hosts: %+v", r)
	}
	if r := check([]string{testAdminGroup}, AuthorizeRequest{Api: computeAPI, Resource: "hosts", Verb: "get"}); r.Allowed {
		t.Errorf("a namespace's admin on hosts: %+v", r)
	}
	if len(asked) != 2 || asked[0] != computeAPI+" hosts" {
		t.Errorf("prechecks: %v", asked)
	}
	// Kayra's own api, in a namespace: as RequireClusterRBAC decides it
	if r := check([]string{testAdminGroup}, AuthorizeRequest{Namespace: testNamespace, Api: AuthorizationAPI, Resource: "roles", Verb: "create"}); !r.Allowed {
		t.Errorf("a namespace's admin on its roles: %+v", r)
	}
	if r := check([]string{platformGroup}, AuthorizeRequest{Namespace: testNamespace, Api: AuthorizationAPI, Resource: "roles", Verb: "create"}); r.Allowed {
		t.Errorf("the platform on a tenant's roles: %+v", r)
	}
	// Kayra's own api, cluster-scoped: the sysadmin
	if r := check([]string{testSysadminGroup}, AuthorizeRequest{Api: AuthorizationAPI, Resource: "clusterroles", Verb: "create"}); !r.Allowed {
		t.Errorf("the sysadmin on clusterroles: %+v", r)
	}
}

// MemberNamespaces and IsNamespaceMember: the namespaces whose own
// groups, or the cluster groups scoped to them, name the caller or a group
// of theirs, whatever their roles.
func TestMemberNamespaces(t *testing.T) {
	repo := newTestRepo(t)
	seedClusterRBAC(t, repo, testAdminGroup, testNamespace) // admins of myns, a cluster group scoped to it
	for ns, g := range map[string]Group{
		"acme":  {Name: "devs", Groups: []string{"sandbox-acme-devs"}},
		"other": {Name: "jdoe", Users: []string{"jdoe"}},
		"none":  {Name: "nobody", Groups: []string{"sandbox-nobody"}},
	} {
		g.Metadata = Metadata{Namespace: ns}
		if err := repo.PutNamespaceGroup(ns, &g); err != nil {
			t.Fatal(err)
		}
	}
	groups := []string{"sandbox-acme-devs", testAdminGroup}
	got, err := repo.MemberNamespaces("jdoe", groups)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for ns := range got {
		names = append(names, ns)
	}
	slices.Sort(names)
	if want := "acme myns other"; strings.Join(names, " ") != want {
		t.Errorf("namespaces: %v, want %s", names, want)
	}
	for ns, want := range map[string]bool{"acme": true, testNamespace: true, "other": true, "none": false, "empty": false} {
		if in, err := repo.IsNamespaceMember(ns, "jdoe", groups); err != nil || in != want {
			t.Errorf("%s: %v %v, want %v", ns, in, err, want)
		}
	}
	if got, _ := repo.MemberNamespaces("x", nil); len(got) != 0 {
		t.Errorf("a stranger's: %v", got)
	}
}
