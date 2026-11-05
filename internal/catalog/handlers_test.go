package catalog

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/middleware"
	"github.com/infrapi/kayra/internal/rbac"
	"github.com/infrapi/kayra/internal/store"
)

func noopGate(c *gin.Context) {}

// fakeAuthGate stands in for middleware.Authenticator.Middleware: it
// trusts userID/groups outright instead of verifying a bearer token.
func fakeAuthGate(userID string, groups ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		middleware.SetAuth(c, &middleware.AuthContext{UserID: userID, Groups: groups})
		c.Next()
	}
}

const (
	testNamespace      = "myns"
	testAdmin          = "test-admin"
	testAdminGroup     = "sandbox-myns-sysadmin"
	testDeployPlatform = "sandbox"
	testDeployRegion   = "eu-west-1"
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

// seedClusterRBAC writes the cluster group/role/rolebinding that grants
// anyone resolved with callerGroup rbac.SubscriptionAPI:"*" rights in
// namespace, bypassing HTTP — exactly what the spec's cluster bootstrap
// flow produces (this package's own tests only ever exercise Subscription
// routes, gated on SubscriptionAPI — see internal/rbac's own test
// helper of the same name for the AuthorizationAPI-gated groups/roles/
// rolebindings equivalent). Duplicated here since it operates on exported
// rbac types and _test.go files can't be imported across packages.
func seedClusterRBAC(t *testing.T, repo *rbac.Repository, callerGroup, namespace string) {
	t.Helper()

	groupName := namespace + "-group-sysadmin"
	roleName := namespace + "-role-sysadmin"
	bindingName := namespace + "-binding-sysadmin"
	meta := rbac.Metadata{Namespace: namespace}

	if err := repo.PutClusterGroup(rbac.Group{
		Name: groupName, Metadata: meta,
		Groups: []string{callerGroup},
	}); err != nil {
		t.Fatalf("seedClusterRBAC PutClusterGroup: %v", err)
	}
	if err := repo.PutClusterRole(rbac.Role{
		Name: roleName, Metadata: meta,
		Rules: []rbac.Rule{{Apis: []string{rbac.SubscriptionAPI}, Resources: []string{"*"}, Verbs: []string{"*"}}},
	}); err != nil {
		t.Fatalf("seedClusterRBAC PutClusterRole: %v", err)
	}
	if err := repo.PutClusterRoleBinding(rbac.RoleBinding{
		Name: bindingName, Metadata: meta, Role: roleName, Groups: []string{groupName},
	}); err != nil {
		t.Fatalf("seedClusterRBAC PutClusterRoleBinding: %v", err)
	}
}

// newTestEngine builds a catalog.Repository and an rbac.Repository
// against the same underlying store (exactly as apiserver.Build wires
// them), seeds testAdmin with full cluster rbac rights in testNamespace,
// and registers every catalog route.
func newTestEngine(t *testing.T) (*gin.Engine, *Repository) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	keys := store.NewKeys("")

	catalogRepo := NewRepository(s, keys)
	rbacRepo := rbac.NewRepository(s, keys)
	seedClusterRBAC(t, rbacRepo, testAdminGroup, testNamespace)

	engine := gin.New()
	RegisterStackRoutes(engine, catalogRepo, noopGate, testDeployPlatform, testDeployRegion)
	RegisterNamespaceRoutes(engine, catalogRepo, rbacRepo, fakeAuthGate(testAdmin, testAdminGroup), testDeployPlatform, testDeployRegion)
	RegisterNamespaceCollectionRoutes(engine, catalogRepo, noopGate)
	return engine, catalogRepo
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
