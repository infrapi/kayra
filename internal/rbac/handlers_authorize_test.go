package rbac

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestAuthorizeRouteOrder confirms the handler's own sequencing: the
// namespace precheck runs first, membership before any api precheck (a
// non-member never reaches it, so learns nothing about subscriptions),
// and an api precheck failure is returned as-is before any role is
// consulted.
func TestAuthorizeRouteOrder(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var calls []string
	prechecks := func(nsErr, apiErr *liberrors.Error) Prechecks {
		return Prechecks{
			Namespace: func(string) *liberrors.Error { calls = append(calls, "namespace"); return nsErr },
			Api:       func(string, string) *liberrors.Error { calls = append(calls, "api"); return apiErr },
		}
	}
	forbidden := liberrors.New(http.StatusForbidden, "test", "namespace \"core\" is not subscribed to api \"compute.example.com\"")
	missing := liberrors.New(http.StatusNotFound, "test", "namespace \"core\" not found")

	cases := []struct {
		desc      string
		member    bool
		nsErr     *liberrors.Error
		apiErr    *liberrors.Error
		wantCode  int
		wantBody  string
		wantCalls string
	}{
		{"namespace precheck fails first", true, missing, forbidden, http.StatusNotFound, "not found", "namespace"},
		{"non-member stops before the api precheck", false, nil, forbidden, http.StatusOK, "not a member", "namespace"},
		{"member reaches the api precheck", true, nil, forbidden, http.StatusForbidden, "not subscribed", "namespace,api"},
		{"member, prechecks pass, role decides", true, nil, nil, http.StatusOK, `"allowed":true`, "namespace,api"},
	}
	for _, tc := range cases {
		calls = nil
		repo := newTestRepo(t)
		if tc.member {
			seedNamespaceRBAC(t, repo, "alice-group", "core", "compute.example.com", "vm", "list")
		}
		engine := gin.New()
		RegisterAuthorizeRoute(engine, repo, fakeAuthGate("alice", "alice-group"), prechecks(tc.nsErr, tc.apiErr))
		w := postCheck(engine)
		if w.Code != tc.wantCode || !bytes.Contains(w.Body.Bytes(), []byte(tc.wantBody)) {
			t.Errorf("%s: status %d body %s, want %d containing %s", tc.desc, w.Code, w.Body.String(), tc.wantCode, tc.wantBody)
		}
		if got := strings.Join(calls, ","); got != tc.wantCalls {
			t.Errorf("%s: prechecks ran %q, want %q", tc.desc, got, tc.wantCalls)
		}
	}
}
