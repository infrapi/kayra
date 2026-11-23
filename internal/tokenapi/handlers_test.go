package tokenapi

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/authz"
	gconfig "github.com/infrapi/kayra/internal/config"
	gcrypto "github.com/infrapi/kayra/internal/crypto"
	"github.com/infrapi/kayra/internal/middleware"
	"github.com/infrapi/kayra/internal/store"
)

type fakeAuthzBackend struct {
	info authz.UserInfo
}

func (f *fakeAuthzBackend) ResolveUser(userID string) (authz.UserInfo, error) { return f.info, nil }

const tokens = "/apis/authorization.infrapi.io/v1/tokens"

// rig is the token routes behind a gate that is the authenticator for a
// bearer token, and the login (as) otherwise.
type rig struct {
	t      *testing.T
	engine *gin.Engine
	store  store.Store
	keys   store.Keys
	as     *middleware.AuthContext // the caller without a bearer token
	opts   *Options
}

func newRig(t *testing.T, cfg *gconfig.Config, backends map[string]*authz.Cached, mutate ...func(*Options)) *rig {
	t.Helper()
	gin.SetMode(gin.TestMode)
	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	keys := store.NewKeys("")
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if backends == nil {
		backends = map[string]*authz.Cached{"idm": authz.NewCached(&fakeAuthzBackend{info: authz.UserInfo{
			ID: "jdoe", Attributes: map[string]string{"email": "jdoe@example.com"}, Groups: []string{"tenant-group-apps"},
		}}, s, keys, "idm")}
	}
	auth := &middleware.Authenticator{Config: cfg, Backends: backends, Store: s, Keys: keys, PatKey: priv}
	r := &rig{t: t, store: s, keys: keys, as: &middleware.AuthContext{UserID: "jdoe", Authorization: "idm", Provider: "okta", Kind: "user"}}
	gate := func(c *gin.Context) {
		if c.GetHeader("Authorization") != "" {
			auth.Middleware()(c)
			return
		}
		middleware.SetAuth(c, r.as)
	}
	opts := Options{Root: "/apis/authorization.infrapi.io/v1", Store: s, Keys: keys, Pub: &priv.PublicKey, Config: cfg,
		TTLs: gconfig.PatDurations{Default: 720 * time.Hour, Max: 2160 * time.Hour}}
	for _, m := range mutate {
		m(&opts)
	}
	r.opts = &opts
	r.engine = gin.New()
	RegisterRoutes(r.engine, gate, opts)
	whoami := func(c *gin.Context) {
		ac, _ := middleware.GetAuth(c)
		c.JSON(http.StatusOK, gin.H{"user_id": ac.UserID, "groups": ac.Groups, "token_id": ac.TokenID})
	}
	r.engine.GET("/whoami", auth.Middleware(), whoami)
	r.engine.Any("/apis/:api/:version/*rest", auth.Middleware(), whoami)
	r.engine.GET("/oauth2/sessions", auth.Middleware(), whoami)
	r.engine.GET("/oauth2/userinfo", auth.Middleware(), whoami)
	r.engine.Any("/apis", auth.Middleware(), whoami)
	return r
}

func (r *rig) do(method, path, token, body string) (int, string) {
	r.t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.engine.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func (r *rig) create(body string) created {
	r.t.Helper()
	code, out := r.do(http.MethodPost, tokens, "", body)
	if code != http.StatusCreated {
		r.t.Fatalf("create %s: %d %s", body, code, out)
	}
	var c created
	_ = json.Unmarshal([]byte(out), &c)
	return c
}

func idmConfig() *gconfig.Config {
	return &gconfig.Config{Authorizations: map[string]gconfig.AuthorizationBackend{"idm": {}}}
}

func TestCreateListUseRevoke(t *testing.T) {
	r := newRig(t, idmConfig(), nil)

	c := r.create(`{"name": "laptop"}`)
	if !gcrypto.IsToken(c.Secret) || c.ID == "" || c.Name != "laptop" || c.User != "jdoe" {
		t.Fatalf("created = %+v", c)
	}
	if d := c.ExpiresAt.Sub(c.CreatedAt); d != 720*time.Hour {
		t.Fatalf("lifetime %s, want the default 720h", d)
	}

	// used: the user, their groups live, the token's id; its last use noted
	code, out := r.do(http.MethodGet, "/whoami", c.Secret, "")
	if code != http.StatusOK || !strings.Contains(out, `"user_id":"jdoe"`) || !strings.Contains(out, `"tenant-group-apps"`) || !strings.Contains(out, c.ID) {
		t.Fatalf("whoami: %d %s", code, out)
	}

	// listed, its secret never
	code, out = r.do(http.MethodGet, tokens, "", "")
	if code != http.StatusOK || !strings.Contains(out, c.ID) || strings.Contains(out, c.Secret) || strings.Contains(out, "hash") || !strings.Contains(out, "last_used_at") {
		t.Fatalf("list: %d %s", code, out)
	}

	// a token creates no other, but lists its user's
	if code, out := r.do(http.MethodPost, tokens, c.Secret, `{"name": "more"}`); code != http.StatusForbidden || !strings.Contains(out, "creates no other") {
		t.Fatalf("a PAT creating a PAT: %d %s", code, out)
	}
	if code, _ := r.do(http.MethodGet, tokens, c.Secret, ""); code != http.StatusOK {
		t.Fatalf("a PAT listing: %d", code)
	}

	// revoked by its id
	if code, _ := r.do(http.MethodDelete, tokens+"/nope", "", ""); code != http.StatusNotFound {
		t.Fatalf("revoke a missing one: %d", code)
	}
	if code, _ := r.do(http.MethodDelete, tokens+"/"+c.ID, "", ""); code != http.StatusNoContent {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := r.do(http.MethodGet, "/whoami", c.Secret, ""); code != http.StatusUnauthorized {
		t.Fatalf("revoked, still used: %d", code)
	}
	if _, out := r.do(http.MethodGet, tokens, "", ""); out != "[]" {
		t.Fatalf("list after revocation: %s", out)
	}
}

func TestCreateRefusals(t *testing.T) {
	r := newRig(t, idmConfig(), nil)
	for body, want := range map[string]string{
		`{}`:                                   "name",
		`{"name": "  "}`:                       "name",
		`{"name": "x", "expires_in": "2161h"}`: "more than the 2160h0m0s",
		`{"name": "x", "expires_in": "later"}`: "a duration",
		`{"name": "x", "scope": {"apis": []}}`: "scope",
		`{"name": "x", "scope": {"apis": ["compute.infrapi.io"], "verbs": [""]}}`: "scope",
		`not json`: "invalid",
	} {
		if code, out := r.do(http.MethodPost, tokens, "", body); code != http.StatusBadRequest || !strings.Contains(out, want) {
			t.Errorf("%s: %d %s, want 400 %q", body, code, out, want)
		}
	}
	r.as = &middleware.AuthContext{UserID: "system:serviceaccount:core:deployer"}
	if code, _ := r.do(http.MethodPost, tokens, "", `{"name": "x"}`); code != http.StatusForbidden {
		t.Fatalf("a service account's PAT: %d", code)
	}
}

func TestExpired(t *testing.T) {
	r := newRig(t, idmConfig(), nil, func(o *Options) { o.Now = func() time.Time { return time.Now().Add(-2 * time.Hour) } })
	c := r.create(`{"name": "old", "expires_in": "1h"}`)
	if code, out := r.do(http.MethodGet, "/whoami", c.Secret, ""); code != http.StatusUnauthorized || !strings.Contains(out, "expired") {
		t.Fatalf("expired: %d %s", code, out)
	}
}

// TestScope: a scoped token sends only what its scope grants, read from
// the request as /check reads it.
func TestScope(t *testing.T) {
	r := newRig(t, idmConfig(), nil)
	c := r.create(`{"name": "ro", "scope": {"apis": ["compute.infrapi.io"], "verbs": ["get", "list"]}}`)
	for _, tt := range []struct {
		method, path string
		code         int
	}{
		{http.MethodGet, "/apis/compute.infrapi.io/v1/namespaces/core/vms", http.StatusOK},
		{http.MethodGet, "/apis/compute.infrapi.io/v1/namespaces/core/vms/web-1", http.StatusOK},
		{http.MethodGet, "/apis/compute.infrapi.io/v1/flavors", http.StatusOK},
		{http.MethodPost, "/apis/compute.infrapi.io/v1/namespaces/core/vms", http.StatusForbidden},
		{http.MethodDelete, "/apis/compute.infrapi.io/v1/namespaces/core/vms/web-1", http.StatusForbidden},
		{http.MethodGet, "/apis/vault.infrapi.io/v1/namespaces/core/secrets", http.StatusForbidden},
		{http.MethodGet, tokens, http.StatusForbidden}, // another api: authorization's
		{http.MethodPost, "/apis/authorization.infrapi.io/v1/check", http.StatusOK},
		{http.MethodGet, "/oauth2/userinfo", http.StatusOK},
		{http.MethodGet, "/apis", http.StatusOK},
		{http.MethodPost, "/apis", http.StatusForbidden},
		{http.MethodGet, "/oauth2/sessions", http.StatusForbidden},
		{http.MethodGet, "/whoami", http.StatusForbidden},
		{http.MethodGet, "/apis/compute.infrapi.io/v1/", http.StatusForbidden},
	} {
		if code, out := r.do(tt.method, tt.path, c.Secret, ""); code != tt.code {
			t.Errorf("%s %s: %d %s, want %d", tt.method, tt.path, code, out, tt.code)
		}
	}
	// the unscoped one: everything its user may
	all := r.create(`{"name": "all"}`)
	if code, _ := r.do(http.MethodDelete, "/apis/compute.infrapi.io/v1/namespaces/core/vms/web-1", all.Secret, ""); code != http.StatusOK {
		t.Fatalf("unscoped: %d", code)
	}
}

func TestOtherUsersTokens(t *testing.T) {
	var verbs []string
	r := newRig(t, idmConfig(), nil, func(o *Options) {
		o.CanManageOthers = func(ac *middleware.AuthContext, verb string) bool {
			verbs = append(verbs, verb)
			return ac.UserID == "root"
		}
	})
	c := r.create(`{"name": "laptop"}`)
	r.as = &middleware.AuthContext{UserID: "mallory", Kind: "user"}
	if code, _ := r.do(http.MethodGet, tokens+"?user=jdoe", "", ""); code != http.StatusForbidden {
		t.Fatalf("another's list: %d", code)
	}
	if code, _ := r.do(http.MethodDelete, tokens+"/"+c.ID+"?user=jdoe", "", ""); code != http.StatusForbidden {
		t.Fatalf("another's revoke: %d", code)
	}
	if code, out := r.do(http.MethodGet, tokens, "", ""); code != http.StatusOK || out != "[]" {
		t.Fatalf("their own: %d %s", code, out)
	}
	r.as = &middleware.AuthContext{UserID: "root", Kind: "user"}
	if code, out := r.do(http.MethodGet, tokens+"?user=jdoe", "", ""); code != http.StatusOK || !strings.Contains(out, c.ID) {
		t.Fatalf("root lists jdoe's: %d %s", code, out)
	}
	if code, _ := r.do(http.MethodDelete, tokens+"/"+c.ID+"?user=jdoe", "", ""); code != http.StatusNoContent {
		t.Fatalf("root revokes jdoe's: %d", code)
	}
	if strings.Join(verbs, ",") != "list,delete,list,delete" {
		t.Fatalf("verbs asked = %v", verbs)
	}
}

// TestSnapshotsGroupsForClaimsBackend: a token minted under a
// claims-backed authorization backend keeps the groups resolved at its
// creation, there being no directory to resolve them from later.
func TestSnapshotsGroupsForClaimsBackend(t *testing.T) {
	cfg := &gconfig.Config{Authorizations: map[string]gconfig.AuthorizationBackend{
		"okta": {Claims: &gconfig.ClaimsAuthzConfig{From: "token", GroupsField: "MemberOf"}},
	}}
	r := newRig(t, cfg, map[string]*authz.Cached{})
	r.as = &middleware.AuthContext{UserID: "jdoe", Authorization: "okta", Provider: "okta", Kind: "user",
		Groups: []string{"sandbox-core-sysadmin"}, Attributes: map[string]string{"email": "jdoe@example.com"}}
	c := r.create(`{"name": "laptop"}`)
	if code, out := r.do(http.MethodGet, "/whoami", c.Secret, ""); code != http.StatusOK || !strings.Contains(out, `"groups":["sandbox-core-sysadmin"]`) {
		t.Fatalf("whoami: %d %s", code, out)
	}
}

func TestUnknownTokenRejected(t *testing.T) {
	r := newRig(t, idmConfig(), nil)
	fake, err := gcrypto.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := r.do(http.MethodGet, "/whoami", fake, ""); code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
}
