package system

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/catalog"
	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/middleware"
	"github.com/infrapi/kayra/internal/rbac"
	"github.com/infrapi/kayra/internal/store"
)

const sysadminGroup = "sandbox-core-sysadmin"

// newEngine mounts the system API, every request authenticated as
// userID with groups, the built-in sysadmin binding sysadminGroup's.
func newEngine(t *testing.T, userID string, groups ...string) (*gin.Engine, *catalog.Repository, *rbac.Repository) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	keys := store.NewKeys("")
	repo, rbacRepo := catalog.NewRepository(s, keys), rbac.NewRepository(s, keys)
	rbacRepo.SetSysadmin([]string{sysadminGroup})

	engine := gin.New()
	r := engine.Group("", func(c *gin.Context) {
		middleware.SetAuth(c, &middleware.AuthContext{UserID: userID, Groups: groups})
		c.Next()
	}, httpapi.WithRequest)
	Register(r, NewServer(repo, rbacRepo))
	return engine, repo, rbacRepo
}

func doJSON(t *testing.T, engine *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		if data, err = json.Marshal(body); err != nil {
			t.Fatalf("Marshal: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

const namespaces = "/apis/system.infrapi.io/v1/namespaces"

func TestNamespaceCollectionCRUD(t *testing.T) {
	engine, repo, _ := newEngine(t, "root", sysadminGroup)

	w := doJSON(t, engine, http.MethodPost, namespaces, map[string]any{"name": "core"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: status %d, body %s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// a namespace is always created disabled: there is no request field
	// that can make it come back active.
	if body["name"] != "core" || body["active"] == true {
		t.Fatalf("create response = %v, want inactive", body)
	}

	if w = doJSON(t, engine, http.MethodGet, namespaces+"/core", nil); w.Code != http.StatusOK {
		t.Fatalf("get: status %d, body %s", w.Code, w.Body.String())
	}
	if w = doJSON(t, engine, http.MethodGet, namespaces+"/does-not-exist", nil); w.Code != http.StatusNotFound {
		t.Fatalf("get missing: status %d, want 404", w.Code)
	}

	// only the internal activation path can flip it — not any HTTP route.
	if err := repo.ActivateNamespace("core"); err != nil {
		t.Fatalf("ActivateNamespace: %v", err)
	}
	w = doJSON(t, engine, http.MethodGet, namespaces+"/core", nil)
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if body["active"] != true {
		t.Fatalf("get after ActivateNamespace = %v, want active=true", body)
	}

	if w = doJSON(t, engine, http.MethodDelete, namespaces+"/core", nil); w.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d, body %s", w.Code, w.Body.String())
	}
	if w = doJSON(t, engine, http.MethodGet, namespaces+"/core", nil); w.Code != http.StatusNotFound {
		t.Fatalf("get after delete: status %d, want 404", w.Code)
	}
	if w = doJSON(t, engine, http.MethodDelete, namespaces+"/core", nil); w.Code != http.StatusNotFound {
		t.Fatalf("delete missing: status %d, want 404", w.Code)
	}
}

func TestNamespaceCreateRequiresName(t *testing.T) {
	engine, _, _ := newEngine(t, "root", sysadminGroup)
	if w := doJSON(t, engine, http.MethodPost, namespaces, map[string]any{}); w.Code != http.StatusBadRequest {
		t.Fatalf("missing name: status %d, want 400, body %s", w.Code, w.Body.String())
	}
}

// Writes are decided on the cluster RBAC: a caller it grants nothing is
// refused.
func TestNamespaceWritesNeedClusterRBAC(t *testing.T) {
	engine, repo, _ := newEngine(t, "nobody")
	if err := repo.PutNamespace(&catalog.Namespace{Name: "core"}); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, engine, http.MethodPost, namespaces, map[string]any{"name": "other"}); w.Code != http.StatusForbidden {
		t.Fatalf("create: status = %d, want 403, body %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, engine, http.MethodDelete, namespaces+"/core", nil); w.Code != http.StatusForbidden {
		t.Fatalf("delete: status = %d, want 403, body %s", w.Code, w.Body.String())
	}
}

func TestListNamespacesHTTP(t *testing.T) {
	engine, _, _ := newEngine(t, "root", sysadminGroup)
	doJSON(t, engine, http.MethodPost, namespaces, map[string]any{"name": "core"})

	w := doJSON(t, engine, http.MethodGet, namespaces, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: status %d, body %s", w.Code, w.Body.String())
	}
	var list []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(list) != 1 || list[0]["name"] != "core" {
		t.Fatalf("list = %v, want core", list)
	}
}

// Anyone else reads the namespaces they are a member of: listed, the
// others left out; got, the others refused.
func TestNamespacesOfAMember(t *testing.T) {
	engine, repo, rbacRepo := newEngine(t, "jdoe")
	for _, ns := range []string{"acme", "core"} {
		if err := repo.PutNamespace(&catalog.Namespace{Name: ns}); err != nil {
			t.Fatal(err)
		}
	}
	if err := rbacRepo.PutNamespaceGroup("acme", &rbac.Group{Name: "devs", Metadata: rbac.Metadata{Namespace: "acme"}, Users: []string{"jdoe"}}); err != nil {
		t.Fatal(err)
	}

	w := doJSON(t, engine, http.MethodGet, namespaces, nil)
	var list []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || w.Code != http.StatusOK {
		t.Fatalf("list: status %d, body %s", w.Code, w.Body.String())
	}
	if len(list) != 1 || list[0]["name"] != "acme" {
		t.Fatalf("list = %v, want acme only", list)
	}
	if w := doJSON(t, engine, http.MethodGet, namespaces+"/acme", nil); w.Code != http.StatusOK {
		t.Fatalf("get acme: status %d, body %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, engine, http.MethodGet, namespaces+"/core", nil); w.Code != http.StatusForbidden {
		t.Fatalf("get core: status %d, want 403, body %s", w.Code, w.Body.String())
	}
}
