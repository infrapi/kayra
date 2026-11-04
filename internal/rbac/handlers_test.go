package rbac

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/middleware"
)

func noopGate(c *gin.Context) {}

func containsGroupNamed(groups []Group, name string) bool {
	for _, g := range groups {
		if g.Name == name {
			return true
		}
	}
	return false
}

// fakeAuthGate stands in for middleware.Authenticator.Middleware: it
// trusts userID/groups outright instead of verifying a bearer token, so
// tests can exercise the requireClusterRBAC gate without a real JWT/PAT
// flow. groups mirrors what /oauth2/userinfo would have resolved from the
// caller's memberOf (post member_regex), e.g. "sandbox-core-sysadmin".
func fakeAuthGate(userID string, groups ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		middleware.SetAuth(c, &middleware.AuthContext{UserID: userID, Groups: groups})
		c.Next()
	}
}

// testNamespace is the namespace every pre-existing CRUD test exercises;
// seedClusterRBAC grants testAdmin (carrying testAdminGroup) full rights
// there so those tests keep testing CRUD, not the new authorization gate.
const (
	testNamespace  = "myns"
	testAdmin      = "test-admin"
	testAdminGroup = "sandbox-myns-sysadmin"
)

// seedClusterRBAC writes the cluster group/role/rolebinding that grants
// anyone resolved with callerGroup AuthorizationAPI:"*" rights in
// namespace, bypassing HTTP — exactly what the spec's cluster bootstrap
// flow produces. CanManageNamespaceRBAC matches against the caller's
// resolved groups directly, without any membership sync — real LDAP
// groups nest other groups inside a group's "member" attribute, so a
// flat synced member list could never be relied on to contain the
// calling user.
func seedClusterRBAC(t *testing.T, repo *Repository, callerGroup, namespace string) {
	t.Helper()

	groupName := namespace + "-group-sysadmin"
	roleName := namespace + "-role-sysadmin"
	bindingName := namespace + "-binding-sysadmin"
	meta := Metadata{Namespace: namespace}

	if err := repo.PutClusterGroup(Group{
		Name: groupName, Metadata: meta,
		Groups: []string{callerGroup},
	}); err != nil {
		t.Fatalf("seedClusterRBAC PutClusterGroup: %v", err)
	}
	if err := repo.PutClusterRole(Role{
		Name: roleName, Metadata: meta,
		Rules: []Rule{{Apis: []string{AuthorizationAPI}, Resources: []string{"*"}, Verbs: []string{"*"}}},
	}); err != nil {
		t.Fatalf("seedClusterRBAC PutClusterRole: %v", err)
	}
	if err := repo.PutClusterRoleBinding(RoleBinding{
		Name: bindingName, Metadata: meta, Role: roleName, Groups: []string{groupName},
	}); err != nil {
		t.Fatalf("seedClusterRBAC PutClusterRoleBinding: %v", err)
	}
}

func newTestEngine(t *testing.T) (*gin.Engine, *Repository) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	repo := newTestRepo(t)
	seedClusterRBAC(t, repo, testAdminGroup, testNamespace)

	engine := gin.New()
	RegisterClusterRoutes(engine, repo, noopGate)
	RegisterNamespaceRoutes(engine, repo, fakeAuthGate(testAdmin, testAdminGroup))
	return engine, repo
}

func doJSON(t *testing.T, engine *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

func TestClusterGroupRoleBindingFlow(t *testing.T) {
	engine, _ := newTestEngine(t)

	meta := Metadata{Namespace: "thetenant", Region: "eu-west-1", Platform: "sandbox"}

	w := doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/clustergroups", Group{
		Name: "thetenant-group-sysadmin", Metadata: meta,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create group: status %d, body %s", w.Code, w.Body.String())
	}

	w = doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/clusterroles", Role{
		Name: "thetenant-role-sysadmin", Metadata: meta,
		Rules: []Rule{{Apis: []string{AuthorizationAPI}, Resources: []string{"*"}, Verbs: []string{"*"}}},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create role: status %d, body %s", w.Code, w.Body.String())
	}

	w = doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/clusterrolebindings", RoleBinding{
		Name: "thetenant-binding-sysadmin", Metadata: meta,
		Role: "thetenant-role-sysadmin", Groups: []string{"thetenant-group-sysadmin"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create rolebinding: status %d, body %s", w.Code, w.Body.String())
	}
}

func TestClusterRoleBindingRejectsMetadataMismatch(t *testing.T) {
	engine, _ := newTestEngine(t)

	meta := Metadata{Namespace: "thetenant", Region: "eu-west-1", Platform: "sandbox"}
	otherMeta := Metadata{Namespace: "other", Region: "eu-west-1", Platform: "sandbox"}

	doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/clusterroles", Role{Name: "r1", Metadata: meta})

	w := doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/clusterrolebindings", RoleBinding{
		Name: "b1", Metadata: otherMeta, Role: "r1",
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("create rolebinding with mismatched metadata: status %d, want 409, body %s", w.Code, w.Body.String())
	}
}

func TestNamespaceGroupDefaultsMetadataNamespace(t *testing.T) {
	engine, repo := newTestEngine(t)

	w := doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/namespaces/myns/groups", Group{
		Name:   "myns-group-apps",
		Groups: []string{"group-a"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create namespace group: status %d, body %s", w.Code, w.Body.String())
	}

	g, err := repo.GetNamespaceGroup("myns", "myns-group-apps")
	if err != nil {
		t.Fatalf("GetNamespaceGroup: %v", err)
	}
	if g.Metadata.Namespace != "myns" {
		t.Fatalf("Metadata.Namespace = %q, want myns (defaulted from path)", g.Metadata.Namespace)
	}
}

func TestNamespaceGroupRejectsMismatchedNamespace(t *testing.T) {
	engine, _ := newTestEngine(t)

	w := doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/namespaces/myns/groups", Group{
		Name:     "myns-group-apps",
		Metadata: Metadata{Namespace: "otherns"},
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body %s", w.Code, w.Body.String())
	}
}

func TestClusterGroupCRUD(t *testing.T) {
	engine, _ := newTestEngine(t)

	doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/clustergroups", Group{Name: "g1", Description: "v1"})

	// list
	w := doJSON(t, engine, http.MethodGet, "/apis/authorization.example.com/v1/clustergroups", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: status %d, body %s", w.Code, w.Body.String())
	}
	var groups []Group
	if err := json.Unmarshal(w.Body.Bytes(), &groups); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// seedClusterRBAC also writes a cluster group for the test-admin
	// bootstrap, so assert g1 is present rather than requiring it alone.
	if !containsGroupNamed(groups, "g1") {
		t.Fatalf("list = %v, want a g1 entry", groups)
	}

	// get one
	w = doJSON(t, engine, http.MethodGet, "/apis/authorization.example.com/v1/clustergroups/g1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: status %d, body %s", w.Code, w.Body.String())
	}

	// get missing -> 404
	w = doJSON(t, engine, http.MethodGet, "/apis/authorization.example.com/v1/clustergroups/missing", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("get missing: status %d, want 404, body %s", w.Code, w.Body.String())
	}

	// update
	w = doJSON(t, engine, http.MethodPut, "/apis/authorization.example.com/v1/clustergroups/g1", Group{Name: "ignored-should-use-path", Description: "v2"})
	if w.Code != http.StatusOK {
		t.Fatalf("update: status %d, body %s", w.Code, w.Body.String())
	}
	var updated Group
	if err := json.Unmarshal(w.Body.Bytes(), &updated); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if updated.Name != "g1" || updated.Description != "v2" {
		t.Fatalf("update response = %+v, want Name=g1 Description=v2 (path name wins over body)", updated)
	}

	// update missing -> 404, and must not create it
	w = doJSON(t, engine, http.MethodPut, "/apis/authorization.example.com/v1/clustergroups/missing", Group{Description: "x"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("update missing: status %d, want 404, body %s", w.Code, w.Body.String())
	}

	// delete
	w = doJSON(t, engine, http.MethodDelete, "/apis/authorization.example.com/v1/clustergroups/g1", nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d, body %s", w.Code, w.Body.String())
	}
	w = doJSON(t, engine, http.MethodGet, "/apis/authorization.example.com/v1/clustergroups/g1", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("get after delete: status %d, want 404", w.Code)
	}

	// delete missing -> 404
	w = doJSON(t, engine, http.MethodDelete, "/apis/authorization.example.com/v1/clustergroups/g1", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("delete missing: status %d, want 404", w.Code)
	}
}

func TestClusterRoleBindingUpdateRevalidatesMetadata(t *testing.T) {
	engine, _ := newTestEngine(t)

	meta := Metadata{Namespace: "thetenant", Region: "eu-west-1", Platform: "sandbox"}
	otherMeta := Metadata{Namespace: "other", Region: "eu-west-1", Platform: "sandbox"}

	doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/clusterroles", Role{Name: "r1", Metadata: meta})
	doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/clusterrolebindings", RoleBinding{Name: "b1", Metadata: meta, Role: "r1"})

	// valid update
	w := doJSON(t, engine, http.MethodPut, "/apis/authorization.example.com/v1/clusterrolebindings/b1", RoleBinding{Metadata: meta, Role: "r1", Groups: []string{}})
	if w.Code != http.StatusOK {
		t.Fatalf("update: status %d, body %s", w.Code, w.Body.String())
	}

	// update that would mismatch the role's metadata is rejected, same as create
	w = doJSON(t, engine, http.MethodPut, "/apis/authorization.example.com/v1/clusterrolebindings/b1", RoleBinding{Metadata: otherMeta, Role: "r1"})
	if w.Code != http.StatusConflict {
		t.Fatalf("update with mismatched metadata: status %d, want 409, body %s", w.Code, w.Body.String())
	}
}

func TestNamespaceRoleCRUD(t *testing.T) {
	engine, _ := newTestEngine(t)
	ns := "myns"

	doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/namespaces/"+ns+"/roles", Role{Name: "r1"})

	w := doJSON(t, engine, http.MethodGet, "/apis/authorization.example.com/v1/namespaces/"+ns+"/roles", nil)
	var roles []Role
	if err := json.Unmarshal(w.Body.Bytes(), &roles); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(roles) != 1 || roles[0].Name != "r1" {
		t.Fatalf("list = %v, want [r1]", roles)
	}

	w = doJSON(t, engine, http.MethodPut, "/apis/authorization.example.com/v1/namespaces/"+ns+"/roles/r1", Role{
		Rules: []Rule{{Apis: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"get"}}},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("update: status %d, body %s", w.Code, w.Body.String())
	}

	w = doJSON(t, engine, http.MethodDelete, "/apis/authorization.example.com/v1/namespaces/"+ns+"/roles/r1", nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d, body %s", w.Code, w.Body.String())
	}
	w = doJSON(t, engine, http.MethodGet, "/apis/authorization.example.com/v1/namespaces/"+ns+"/roles/r1", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("get after delete: status %d, want 404", w.Code)
	}
}

func TestNamespaceWriteDeniedWithoutClusterRBAC(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := newTestRepo(t)
	// no seedClusterRBAC: "nobody" has no cluster group membership at all.

	engine := gin.New()
	RegisterClusterRoutes(engine, repo, noopGate)
	RegisterNamespaceRoutes(engine, repo, fakeAuthGate("nobody"))

	w := doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/namespaces/myns/groups", Group{Name: "g1"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body %s", w.Code, w.Body.String())
	}

	// reads are gated too, not just writes.
	w = doJSON(t, engine, http.MethodGet, "/apis/authorization.example.com/v1/namespaces/myns/groups", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("list status = %d, want 403, body %s", w.Code, w.Body.String())
	}
}

func TestNamespaceWriteDeniedOutsideGrantedNamespace(t *testing.T) {
	engine, _ := newTestEngine(t)
	// testAdmin is authorized for "myns" only (seeded by newTestEngine).

	w := doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/namespaces/otherns/groups", Group{Name: "g1"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body %s", w.Code, w.Body.String())
	}
}

func TestNamespaceWriteGrantedEndToEndViaHTTPBootstrap(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := newTestRepo(t)

	engine := gin.New()
	RegisterClusterRoutes(engine, repo, noopGate)
	// jdoe's resolved groups (what /oauth2/userinfo would have returned
	// from their real memberOf, post member_regex) — no sync step needed.
	RegisterNamespaceRoutes(engine, repo, fakeAuthGate("jdoe", "sandbox-thetenant-sysadmin"))

	meta := Metadata{Namespace: "thetenant"}

	// before bootstrap: denied.
	w := doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/namespaces/thetenant/groups", Group{Name: "g1"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("before bootstrap: status = %d, want 403, body %s", w.Code, w.Body.String())
	}

	// the exact cluster bootstrap flow from the spec, driven over HTTP —
	// deliberately no /refresh call: authorization no longer depends on
	// a synced member list, only on the caller's own resolved groups
	// matching the cluster group's configured LDAP source.
	doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/clustergroups", Group{
		Name: "thetenant-group-sysadmin", Metadata: meta,
		Groups: []string{"sandbox-thetenant-sysadmin"},
	})
	doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/clusterroles", Role{
		Name: "thetenant-role-sysadmin", Metadata: meta,
		Rules: []Rule{{Apis: []string{AuthorizationAPI}, Resources: []string{"*"}, Verbs: []string{"*"}}},
	})
	w = doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/clusterrolebindings", RoleBinding{
		Name: "thetenant-binding-sysadmin", Metadata: meta,
		Role: "thetenant-role-sysadmin", Groups: []string{"thetenant-group-sysadmin"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create rolebinding: status %d, body %s", w.Code, w.Body.String())
	}

	// after bootstrap: jdoe can now manage namespace RBAC for "thetenant",
	// with no refresh step ever having run.
	w = doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/namespaces/thetenant/groups", Group{Name: "g1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("after bootstrap: status = %d, want 201, body %s", w.Code, w.Body.String())
	}

	// but still not for an unrelated namespace.
	w = doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/namespaces/otherns/groups", Group{Name: "g1"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("other namespace: status = %d, want 403, body %s", w.Code, w.Body.String())
	}
}

// TestNamespaceWriteGrantedEndToEndViaDirectUserBootstrap is
// TestNamespaceWriteGrantedEndToEndViaHTTPBootstrap's direct-member
// twin: the exact same end-to-end flow, driven over HTTP, but the
// cluster Group names jdoe's user id directly, under Users rather than
// Groups — no group claim in the caller's own resolved groups at all.
func TestNamespaceWriteGrantedEndToEndViaDirectUserBootstrap(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := newTestRepo(t)

	engine := gin.New()
	RegisterClusterRoutes(engine, repo, noopGate)
	// jdoe authenticates with no groups at all — this grant has to come
	// from the direct user source, not from any LDAP group.
	RegisterNamespaceRoutes(engine, repo, fakeAuthGate("jdoe"))

	meta := Metadata{Namespace: "thetenant"}

	// before bootstrap: denied.
	w := doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/namespaces/thetenant/groups", Group{Name: "g1"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("before bootstrap: status = %d, want 403, body %s", w.Code, w.Body.String())
	}

	doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/clustergroups", Group{
		Name: "thetenant-group-jdoe", Metadata: meta,
		Users: []string{"jdoe"},
	})
	doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/clusterroles", Role{
		Name: "thetenant-role-sysadmin", Metadata: meta,
		Rules: []Rule{{Apis: []string{AuthorizationAPI}, Resources: []string{"*"}, Verbs: []string{"*"}}},
	})
	w = doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/clusterrolebindings", RoleBinding{
		Name: "thetenant-binding-sysadmin", Metadata: meta,
		Role: "thetenant-role-sysadmin", Groups: []string{"thetenant-group-jdoe"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create rolebinding: status %d, body %s", w.Code, w.Body.String())
	}

	// after bootstrap: jdoe can now manage namespace RBAC for "thetenant",
	// purely on the strength of being listed directly.
	w = doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/namespaces/thetenant/groups", Group{Name: "g1"})
	if w.Code != http.StatusCreated {
		t.Fatalf("after bootstrap: status = %d, want 201, body %s", w.Code, w.Body.String())
	}

	// but still not for an unrelated namespace.
	w = doJSON(t, engine, http.MethodPost, "/apis/authorization.example.com/v1/namespaces/otherns/groups", Group{Name: "g1"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("other namespace: status = %d, want 403, body %s", w.Code, w.Body.String())
	}
}
