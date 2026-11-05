package rbac

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	liberrors "github.com/infrapi/lib/pkg/errors"
)

func postCheck(engine *gin.Engine) *httptest.ResponseRecorder {
	body := []byte(`{"namespace":"core","api":"compute.example.com","resource":"vm","verb":"list"}`)
	req := httptest.NewRequest(http.MethodPost, "/apis/"+AuthorizationAPI+"/v1/check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

// TestAuthorizeRoutePrecheck confirms a precheck failure is returned
// as-is, before any RBAC rule is evaluated, and that a passing precheck
// falls through to the ordinary allowed/reason decision.
func TestAuthorizeRoutePrecheck(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var gotNamespace, gotApi, gotVerb string
	failing := gin.New()
	RegisterAuthorizeRoute(failing, newTestRepo(t), fakeAuthGate("alice"), func(namespace, api, verb string) *liberrors.Error {
		gotNamespace, gotApi, gotVerb = namespace, api, verb
		return liberrors.New(http.StatusForbidden, "test", "namespace %q is not subscribed to api %q", namespace, api)
	})
	w := postCheck(failing)
	if w.Code != http.StatusForbidden {
		t.Fatalf("failing precheck: status %d, want 403, body %s", w.Code, w.Body.String())
	}
	if gotNamespace != "core" || gotApi != "compute.example.com" || gotVerb != "list" {
		t.Fatalf("precheck got (%q, %q, %q), want (core, compute.example.com, list)", gotNamespace, gotApi, gotVerb)
	}

	passing := gin.New()
	RegisterAuthorizeRoute(passing, newTestRepo(t), fakeAuthGate("alice"), func(string, string, string) *liberrors.Error { return nil })
	w = postCheck(passing)
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(`"allowed":false`)) {
		t.Fatalf("passing precheck: status %d body %s, want 200 allowed:false", w.Code, w.Body.String())
	}
}
