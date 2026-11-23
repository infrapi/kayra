package rbac

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/identity"
)

// fakeIssuer records the machine token it was asked for.
type fakeIssuer struct {
	subject, uid, kind string
	audience           []string
	ttl                time.Duration
}

func (f *fakeIssuer) IssueMachineToken(subject, uid, kind string, audience []string, ttl time.Duration) (string, time.Time, error) {
	f.subject, f.uid, f.kind, f.audience, f.ttl = subject, uid, kind, audience, ttl
	return "signed." + subject, time.Unix(1_000_000, 0).UTC(), nil
}
func (f *fakeIssuer) Resources() []string {
	return []string{"https://kayra.example.com", "https://compute.example.com"}
}
func (f *fakeIssuer) AllowedResource(r string) bool {
	return r == "https://kayra.example.com" || strings.HasPrefix(r, "https://compute.example.com")
}

const saPath = "/apis/authorization.infrapi.io/v1/namespaces/myns/serviceaccounts"

func newSAEngine(t *testing.T, issuer TokenIssuer, gate gin.HandlerFunc) (*gin.Engine, *Repository) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	repo := newTestRepo(t)
	seedClusterRBAC(t, repo, testAdminGroup, testNamespace)
	if gate == nil {
		gate = fakeAuthGate(testAdmin, testAdminGroup)
	}
	engine := gin.New()
	RegisterServiceAccountRoutes(engine, repo, gate, ServiceAccountTokens{Issuer: issuer, DefaultTTL: time.Hour, MaxTTL: 24 * time.Hour})
	RegisterNamespaceRoutes(engine, repo, gate, nil)
	RegisterClusterRoutes(engine, repo, sysadminGate(repo), nil)
	return engine, repo
}

func TestServiceAccountCRUD(t *testing.T) {
	engine, repo := newSAEngine(t, &fakeIssuer{}, nil)

	for _, name := range []string{"", "Deployer", "a_b", strings.Repeat("a", 64)} {
		if w := doJSON(t, engine, http.MethodPost, saPath, ServiceAccount{Name: name}); w.Code != http.StatusBadRequest {
			t.Fatalf("create %q: status %d, want 400", name, w.Code)
		}
	}
	w := doJSON(t, engine, http.MethodPost, saPath, ServiceAccount{Name: "deployer", Description: "CI", UID: "mine"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	var created ServiceAccount
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if created.UID == "" || created.UID == "mine" || created.Metadata.Namespace != "myns" {
		t.Fatalf("created = %+v: a uid of Kayra's, the path's namespace", created)
	}
	if w := doJSON(t, engine, http.MethodPost, saPath, ServiceAccount{Name: "deployer"}); w.Code != http.StatusConflict {
		t.Fatalf("create twice: status %d, want 409", w.Code)
	}
	if w := doJSON(t, engine, http.MethodPost, saPath, ServiceAccount{Name: "x", Metadata: Metadata{Namespace: "other"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("create in another namespace: status %d, want 400", w.Code)
	}

	w = doJSON(t, engine, http.MethodPut, saPath+"/deployer", ServiceAccount{Name: "renamed", Description: "the CI", UID: "forged"})
	if w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body)
	}
	got, _ := repo.GetNamespaceServiceAccount("myns", "deployer")
	if got.UID != created.UID || got.Description != "the CI" || got.Name != "deployer" || !got.CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("updated = %+v: name, uid and creation kept, description changed", got)
	}

	if w := doJSON(t, engine, http.MethodGet, saPath, nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"deployer"`) {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if w := doJSON(t, engine, http.MethodGet, saPath+"/deployer", nil); w.Code != http.StatusOK {
		t.Fatalf("get: %d", w.Code)
	}
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		if w := doJSON(t, engine, m, saPath+"/nope", ServiceAccount{}); w.Code != http.StatusNotFound {
			t.Fatalf("%s a missing one: status %d, want 404", m, w.Code)
		}
	}
	if w := doJSON(t, engine, http.MethodDelete, saPath+"/deployer", nil); w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", w.Code)
	}
	if _, err := repo.GetNamespaceServiceAccount("myns", "deployer"); err == nil {
		t.Fatal("deleted, still there")
	}
}

func TestServiceAccountToken(t *testing.T) {
	issuer := &fakeIssuer{}
	engine, repo := newSAEngine(t, issuer, nil)
	doJSON(t, engine, http.MethodPost, saPath, ServiceAccount{Name: "deployer"})
	sa, _ := repo.GetNamespaceServiceAccount("myns", "deployer")

	// no body: the defaults
	w := doJSON(t, engine, http.MethodPost, saPath+"/deployer/token", nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("token: %d %s", w.Code, w.Body)
	}
	var res tokenResponse
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if res.Token != "signed.system:serviceaccount:myns:deployer" || res.ExpiresAt.IsZero() {
		t.Fatalf("response = %+v", res)
	}
	if issuer.subject != "system:serviceaccount:myns:deployer" || issuer.uid != sa.UID || issuer.kind != identity.KindServiceAccount ||
		issuer.ttl != time.Hour || len(issuer.audience) != 1 || issuer.audience[0] != "https://kayra.example.com" {
		t.Fatalf("issued = %+v", issuer)
	}

	w = doJSON(t, engine, http.MethodPost, saPath+"/deployer/token", tokenRequest{ExpiresIn: "24h", Audience: []string{"https://compute.example.com"}})
	if w.Code != http.StatusCreated || issuer.ttl != 24*time.Hour || issuer.audience[0] != "https://compute.example.com" {
		t.Fatalf("token for compute, 24h: %d %s, %+v", w.Code, w.Body, issuer)
	}

	for _, tt := range []struct {
		body tokenRequest
		want string
	}{
		{tokenRequest{ExpiresIn: "25h"}, "more than the 24h0m0s"},
		{tokenRequest{ExpiresIn: "soon"}, "a duration"},
		{tokenRequest{ExpiresIn: "-1h"}, "a duration"},
		{tokenRequest{Audience: []string{"https://evil.example.com"}}, "not one of the resources"},
	} {
		w := doJSON(t, engine, http.MethodPost, saPath+"/deployer/token", tt.body)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), tt.want) {
			t.Fatalf("%+v: %d %s, want 400 %q", tt.body, w.Code, w.Body, tt.want)
		}
	}
	if w := doJSON(t, engine, http.MethodPost, saPath+"/nope/token", nil); w.Code != http.StatusNotFound {
		t.Fatalf("a missing one's token: %d", w.Code)
	}

	// the authorization server off
	engine, _ = newSAEngine(t, nil, nil)
	doJSON(t, engine, http.MethodPost, saPath, ServiceAccount{Name: "deployer"})
	if w := doJSON(t, engine, http.MethodPost, saPath+"/deployer/token", nil); w.Code != http.StatusNotImplemented {
		t.Fatalf("no issuer: %d, want 501", w.Code)
	}
}

// TestServiceAccountTokenPermission: the token action is a permission of
// its own, apart from managing service accounts.
func TestServiceAccountTokenPermission(t *testing.T) {
	engine, repo := newSAEngine(t, &fakeIssuer{}, fakeAuthGate("ci-admin", "ci-admins"))
	meta := Metadata{Namespace: "myns"}
	_ = repo.PutClusterGroup(&Group{Name: "ci", Metadata: meta, Groups: []string{"ci-admins"}})
	_ = repo.PutClusterRole(&Role{Name: "tokens", Metadata: meta, Rules: []Rule{{Apis: []string{AuthorizationAPI}, Resources: []string{"serviceaccounts/token"}, Verbs: []string{"create"}}}})
	_ = repo.PutClusterRoleBinding(&RoleBinding{Name: "ci-tokens", Metadata: meta, Role: "tokens", Groups: []string{"ci"}})
	_ = repo.PutNamespaceServiceAccount("myns", &ServiceAccount{Name: "deployer", UID: "u1"})

	if w := doJSON(t, engine, http.MethodPost, saPath+"/deployer/token", nil); w.Code != http.StatusCreated {
		t.Fatalf("token with only serviceaccounts/token: %d %s", w.Code, w.Body)
	}
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		if w := doJSON(t, engine, m, saPath, ServiceAccount{Name: "other"}); w.Code != http.StatusForbidden {
			t.Fatalf("%s serviceaccounts with only the token permission: %d, want 403", m, w.Code)
		}
	}
}

func TestGroupMembersValidated(t *testing.T) {
	engine, _ := newSAEngine(t, &fakeIssuer{}, nil)
	ns := "/apis/authorization.infrapi.io/v1/namespaces/myns/groups"
	cluster := "/apis/authorization.infrapi.io/v1/clustergroups"

	for _, tt := range []struct {
		path string
		g    Group
		code int
	}{
		{ns, Group{Name: "ok", ServiceAccounts: []string{"deployer"}, Groups: []string{"system:serviceaccounts:myns", "sre"}}, http.StatusCreated},
		{ns, Group{Name: "u", Users: []string{"system:serviceaccount:myns:deployer"}}, http.StatusBadRequest},
		{ns, Group{Name: "other", Groups: []string{"system:serviceaccounts:other"}}, http.StatusBadRequest},
		{ns, Group{Name: "all", Groups: []string{"system:serviceaccounts"}}, http.StatusBadRequest},
		{ns, Group{Name: "bad", ServiceAccounts: []string{"other:deployer"}}, http.StatusBadRequest},
		{cluster, Group{Name: "c1", Metadata: Metadata{Namespace: "myns"}, ServiceAccounts: []string{"deployer"}}, http.StatusBadRequest},
		{cluster, Group{Name: "c2", Metadata: Metadata{Namespace: "myns"}, Groups: []string{"system:serviceaccounts:myns"}}, http.StatusBadRequest},
		{cluster, Group{Name: "c3", Users: []string{"system:api:compute.infrapi.io"}}, http.StatusBadRequest},
	} {
		if w := doJSON(t, engine, http.MethodPost, tt.path, tt.g); w.Code != tt.code {
			t.Fatalf("%s %+v: %d %s, want %d", tt.path, tt.g, w.Code, w.Body, tt.code)
		}
	}
	// update too
	if w := doJSON(t, engine, http.MethodPut, ns+"/ok", Group{Users: []string{"system:x"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("update a namespace group with a reserved user: %d", w.Code)
	}
	doJSON(t, engine, http.MethodPost, cluster, Group{Name: "c4"})
	if w := doJSON(t, engine, http.MethodPut, cluster+"/c4", Group{ServiceAccounts: []string{"deployer"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("update a cluster group with service accounts: %d", w.Code)
	}
}

// TestServiceAccountAuthorize: a service account holds what its own
// namespace's groups grant it, by name or through its namespace's group,
// and nothing anywhere else: no wildcard, no other namespace, nothing
// cluster-scoped.
func TestServiceAccountAuthorize(t *testing.T) {
	repo := newTestRepo(t)
	repo.SetSysadmin([]string{"system:serviceaccounts"}) // even so
	sa := identity.ServiceAccount("myns", "deployer")
	groups := identity.ServiceAccountGroups("myns")
	const api = "compute.infrapi.io"

	bind := func(ns, group string, g Group) {
		g.Name, g.Metadata = group, Metadata{Namespace: ns}
		_ = repo.PutNamespaceGroup(ns, &g)
		_ = repo.PutNamespaceRole(ns, &Role{Name: "vms", Metadata: g.Metadata, Rules: []Rule{{Apis: []string{api}, Resources: []string{"vms"}, Verbs: []string{"*"}}}})
		_ = repo.PutNamespaceRoleBinding(ns, &RoleBinding{Name: group, Metadata: g.Metadata, Role: "vms", Groups: []string{group}})
	}
	// every wildcard there is, in another namespace and in its own
	bind("other", "everyone", Group{Users: []string{"*", sa}, Groups: []string{"*"}, ServiceAccounts: []string{"deployer"}})
	bind("myns", "everyone", Group{Users: []string{"*"}, Groups: []string{"*"}})
	allowed := func(ns string) bool {
		ok, _, err := repo.Authorize(sa, groups, ns, api, "vms", "create")
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if allowed("other") || allowed("myns") {
		t.Fatal("a wildcard or another namespace's group counts the service account in")
	}

	bind("myns", "ci", Group{ServiceAccounts: []string{"deployer"}})
	if !allowed("myns") {
		t.Fatal("named in its namespace's group: not allowed")
	}
	_ = repo.DeleteNamespaceGroup("myns", "ci")
	bind("myns", "all-sa", Group{Groups: []string{identity.NamespaceServiceAccounts("myns")}})
	if !allowed("myns") {
		t.Fatal("through its namespace's service accounts' group: not allowed")
	}
	if ok, _, _ := repo.Authorize(identity.ServiceAccount("myns", "other"), groups, "myns", api, "vms", "create"); !ok {
		t.Fatal("another service account of the namespace, through its group: not allowed")
	}

	// nothing cluster-scoped, no namespace RBAC management, no membership through a cluster group
	_ = repo.PutClusterGroup(&Group{Name: "all", Metadata: Metadata{Namespace: "myns"}, Groups: []string{"*"}, Users: []string{"*"}})
	_ = repo.PutClusterRole(&Role{Name: "all", Metadata: Metadata{Namespace: "myns"}, Rules: []Rule{all}})
	_ = repo.PutClusterRoleBinding(&RoleBinding{Name: "all", Metadata: Metadata{Namespace: "myns"}, Role: "all", Groups: []string{"all"}})
	_ = repo.PutClusterGroup(&Group{Name: "global", Groups: []string{"*"}, Users: []string{"*"}})
	_ = repo.PutClusterRole(&Role{Name: "global", Rules: []Rule{all}})
	_ = repo.PutClusterRoleBinding(&RoleBinding{Name: "global", Role: "global", Groups: []string{"global"}})
	if ok, _, _ := repo.AuthorizeCluster(sa, groups, api, "flavors", "list"); ok {
		t.Fatal("a cluster-scoped grant")
	}
	if ok, _, _ := repo.CanManageNamespaceRBAC(sa, groups, "myns", AuthorizationAPI, "serviceaccounts/token", "create"); ok {
		t.Fatal("managing its namespace's RBAC")
	}
	if rules, _ := repo.NamespaceRules(sa, groups, "myns"); len(rules) != 1 {
		t.Fatalf("namespace rules = %v: its own namespace role only, none of the cluster's", rules)
	}
	if ns, _ := repo.MemberNamespaces(sa, groups); len(ns) != 1 || !ns["myns"] {
		t.Fatalf("member namespaces = %v, want myns only", ns)
	}
}

func TestServiceAccountContext(t *testing.T) {
	repo := newTestRepo(t)
	_ = repo.PutNamespaceServiceAccount("myns", &ServiceAccount{Name: "deployer", UID: "u1"})
	sub := identity.ServiceAccount("myns", "deployer")

	ac, err := repo.ServiceAccountContext(sub, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if ac.UserID != sub || ac.Kind != identity.KindServiceAccount || len(ac.Groups) != 2 || ac.Groups[1] != "system:serviceaccounts:myns" {
		t.Fatalf("context = %+v", ac)
	}
	for _, tt := range []struct{ sub, uid, want string }{
		{sub, "u0", "an earlier service account"},
		{sub, "", "an earlier service account"},
		{identity.ServiceAccount("myns", "gone"), "u1", "does not exist"},
		{"jdoe", "u1", "is no service account"},
		{"system:serviceaccount:myns", "u1", "is no service account"},
	} {
		if _, err := repo.ServiceAccountContext(tt.sub, tt.uid); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Fatalf("%s/%s: %v, want %q", tt.sub, tt.uid, err, tt.want)
		}
	}
}
