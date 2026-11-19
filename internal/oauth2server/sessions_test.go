package oauth2server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/config"
	"github.com/infrapi/kayra/internal/middleware"
)

// sessionsRig serves the sessions' endpoints, the caller as the
// X-Test-User header says, jdoe's two logins and asmith's one stored.
func sessionsRig(t *testing.T) (*Server, *gin.Engine) {
	t.Helper()
	srv := newTestServer(t, config.OAuth2ServerConfig{})
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	srv.Now = func() time.Time { return now }
	srv.ttl = config.OAuth2Durations{Access: 15 * time.Minute, Refresh: 720 * time.Hour, Idle: 168 * time.Hour}
	for id, f := range map[string]family{
		"s1":    {Client: "infrapi-cli", UserID: "jdoe", Created: now.Add(-time.Hour), LastUsed: now.Add(-time.Minute)},
		"s2":    {Client: "https://claude.ai/oauth/mcp-oauth-client-metadata", UserID: "jdoe", Created: now.Add(-48 * time.Hour), LastUsed: now.Add(-time.Hour)},
		"idle":  {Client: "infrapi-cli", UserID: "jdoe", Created: now.Add(-300 * time.Hour), LastUsed: now.Add(-200 * time.Hour)},
		"other": {Client: "infrapi-cli", UserID: "asmith", Created: now.Add(-time.Hour), LastUsed: now},
	} {
		if err := srv.put("families", id, f, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	srv.CanManageSessions = func(ac *middleware.AuthContext, verb string) bool { return ac.UserID == "root" }
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/oauth2/sessions", func(c *gin.Context) {
		middleware.SetAuth(c, &middleware.AuthContext{UserID: c.GetHeader("X-Test-User")})
	})
	g.GET("", srv.listSessions)
	g.DELETE("", srv.revokeSessions)
	g.DELETE("/:id", srv.revokeSession)
	return srv, r
}

func call(r *gin.Engine, method, path, user string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("X-Test-User", user)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func ids(t *testing.T, w *httptest.ResponseRecorder) []string {
	t.Helper()
	var out []Session
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var got []string
	for _, s := range out {
		got = append(got, s.ID)
	}
	return got
}

func TestSessions(t *testing.T) {
	srv, r := sessionsRig(t)
	// one's own, the latest used first; an idle one is over
	if got := ids(t, call(r, "GET", "/oauth2/sessions", "jdoe")); len(got) != 2 || got[0] != "s1" || got[1] != "s2" {
		t.Fatalf("jdoe's: %v", got)
	}
	// another's: forbidden, unless the cluster RBAC grants it
	if w := call(r, "GET", "/oauth2/sessions?user=asmith", "jdoe"); w.Code != http.StatusForbidden {
		t.Fatalf("asmith's by jdoe: %d", w.Code)
	}
	if got := ids(t, call(r, "GET", "/oauth2/sessions?user=asmith", "root")); len(got) != 1 || got[0] != "other" {
		t.Fatalf("asmith's by root: %v", got)
	}
	// another's session is not found
	if w := call(r, "DELETE", "/oauth2/sessions/other", "jdoe"); w.Code != http.StatusNotFound {
		t.Fatalf("revoke asmith's by jdoe: %d", w.Code)
	}
	// one's own: its access tokens refused at once, by their sid
	if revoked, _ := srv.Revoked(map[string]any{"jti": "a1", "sid": "s1"}); revoked {
		t.Fatal("revoked before")
	}
	if w := call(r, "DELETE", "/oauth2/sessions/s1", "jdoe"); w.Code != http.StatusNoContent {
		t.Fatalf("revoke s1: %d %s", w.Code, w.Body.String())
	}
	if revoked, err := srv.Revoked(map[string]any{"jti": "a1", "sid": "s1"}); !revoked || err != nil {
		t.Fatalf("an access token of s1: %v %v", revoked, err)
	}
	if got := ids(t, call(r, "GET", "/oauth2/sessions", "jdoe")); len(got) != 1 || got[0] != "s2" {
		t.Fatalf("after revoking s1: %v", got)
	}
	// every one of a user's, by an admin
	w := call(r, "DELETE", "/oauth2/sessions?user=asmith", "root")
	if w.Code != http.StatusOK || w.Body.String() != `{"revoked":1}` {
		t.Fatalf("revoke asmith's: %d %s", w.Code, w.Body.String())
	}
	if revoked, _ := srv.Revoked(map[string]any{"sid": "other"}); !revoked {
		t.Fatal("asmith's session not revoked")
	}
	if revoked, _ := srv.Revoked(map[string]any{"jti": "x"}); revoked {
		t.Fatal("a token of no session: revoked")
	}
}
