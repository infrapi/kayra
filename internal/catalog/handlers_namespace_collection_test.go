package catalog

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNamespaceCollectionCRUD(t *testing.T) {
	engine, repo := newTestEngine(t)

	w := doJSON(t, engine, http.MethodPost, "/apis/system.example.com/v1/namespaces", namespaceUpsertRequest{Name: "core"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: status %d, body %s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// a namespace is always created disabled: there is no request field
	// that can make it come back active.
	if body["name"] != "core" || body["active"] != false {
		t.Fatalf("create response = %v, want active=false", body)
	}

	w = doJSON(t, engine, http.MethodGet, "/apis/system.example.com/v1/namespaces/core", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: status %d, body %s", w.Code, w.Body.String())
	}

	w = doJSON(t, engine, http.MethodGet, "/apis/system.example.com/v1/namespaces/does-not-exist", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("get missing: status %d, want 404", w.Code)
	}

	// PUT is a no-op confirmation: active stays computed, and there is
	// nothing else left in the body to change.
	w = doJSON(t, engine, http.MethodPut, "/apis/system.example.com/v1/namespaces/core", namespaceUpsertRequest{})
	if w.Code != http.StatusOK {
		t.Fatalf("update: status %d, body %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if body["active"] != false {
		t.Fatalf("update response = %v, want still active=false", body)
	}

	// only the internal activation path can flip it — not any HTTP route.
	if err := repo.ActivateNamespace("core"); err != nil {
		t.Fatalf("ActivateNamespace: %v", err)
	}
	w = doJSON(t, engine, http.MethodGet, "/apis/system.example.com/v1/namespaces/core", nil)
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if body["active"] != true {
		t.Fatalf("get after ActivateNamespace = %v, want active=true", body)
	}

	w = doJSON(t, engine, http.MethodPut, "/apis/system.example.com/v1/namespaces/missing", namespaceUpsertRequest{})
	if w.Code != http.StatusNotFound {
		t.Fatalf("update missing: status %d, want 404", w.Code)
	}

	w = doJSON(t, engine, http.MethodDelete, "/apis/system.example.com/v1/namespaces/core", nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d, body %s", w.Code, w.Body.String())
	}
	w = doJSON(t, engine, http.MethodGet, "/apis/system.example.com/v1/namespaces/core", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("get after delete: status %d, want 404", w.Code)
	}
}

func TestNamespaceCreateRequiresName(t *testing.T) {
	engine, _ := newTestEngine(t)

	w := doJSON(t, engine, http.MethodPost, "/apis/system.example.com/v1/namespaces", namespaceUpsertRequest{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing name: status %d, want 400, body %s", w.Code, w.Body.String())
	}
}

func TestNamespaceCollectionRequiresSysadminGate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := newTestRepo(t)
	engine := gin.New()
	// a gate that always rejects, standing in for SysadminGate denying
	// a caller with no $platform-core-sysadmin claim.
	rejectGate := func(c *gin.Context) { c.AbortWithStatus(http.StatusForbidden) }
	RegisterNamespaceCollectionRoutes(engine, repo, rejectGate)

	w := doJSON(t, engine, http.MethodPost, "/apis/system.example.com/v1/namespaces", namespaceUpsertRequest{Name: "core"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body %s", w.Code, w.Body.String())
	}
}

func TestListNamespacesHTTP(t *testing.T) {
	engine, _ := newTestEngine(t)

	doJSON(t, engine, http.MethodPost, "/apis/system.example.com/v1/namespaces", namespaceUpsertRequest{Name: "core"})

	w := doJSON(t, engine, http.MethodGet, "/apis/system.example.com/v1/namespaces", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: status %d, body %s", w.Code, w.Body.String())
	}
	var list []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	var found bool
	for _, entry := range list {
		if entry["name"] == "core" {
			found = true
		}
	}
	if !found {
		t.Fatalf("list = %v, want an entry for %q", list, "core")
	}
}
