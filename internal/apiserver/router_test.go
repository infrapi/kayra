package apiserver

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/catalog"
	gconfig "github.com/infrapi/kayra/internal/config"
	gcrypto "github.com/infrapi/kayra/internal/crypto"
	"github.com/infrapi/kayra/internal/middleware"
	libconfig "github.com/infrapi/lib/pkg/config"
)

func testAppConfig() *libconfig.AppConfig {
	return &libconfig.AppConfig{
		AppName:              "kayra-test",
		AppPlatform:          "sandbox",
		AppRegion:            "eu-west-1",
		AppFqdn:              "kayra.local",
		AppLocation:          "dc1",
		AppUrl:               "http://127.0.0.1:0",
		AppListenAddress:     "127.0.0.1:0",
		AppTrustedProxies:    []string{},
		AppCorsAllowOrigins:  []string{"*"},
		AppCorsAllowMethods:  []string{"GET", "POST", "PUT", "DELETE"},
		AppCorsAllowHeaders:  []string{"Origin", "Authorization", "Content-Type"},
		AppCorsExposeHeaders: []string{"Content-Length"},
	}
}

func testKayraConfig(t *testing.T) *gconfig.Config {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	secret := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}))

	usersPath := filepath.Join(t.TempDir(), "users.yaml")
	fixture := "users:\n  - id: bootstrap\n    groups: [sandbox-core-sysadmin]\n    attributes:\n      email: bootstrap@example.com\n" +
		"  - id: nobody\n    groups: [sandbox-nobody]\n"
	if err := os.WriteFile(usersPath, []byte(fixture), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	return &gconfig.Config{
		Database: map[string]gconfig.DatabaseBackend{
			"dev": {Local: &gconfig.LocalConfig{Path: t.TempDir()}},
		},
		Authentifications: map[string]gconfig.AuthProvider{
			"self": {
				Authorization: "dev",
				Local: []gconfig.LocalSigningKey{
					{Enabled: true, Algorithm: "RS256", Issuer: true, Kid: "k1", Secret: secret},
				},
			},
		},
		Authorizations: map[string]gconfig.AuthorizationBackend{
			"dev": {Local: &gconfig.LocalAuthzConfig{Path: usersPath}},
		},
	}
}

// mintSysadminToken signs a self-JWT off cfg's "self" provider via
// gcrypto.MintSelfJWT, so the test can call the cluster endpoints
// Build wires up behind the built-in sysadmin binding.
func mintSysadminToken(t *testing.T, cfg *gconfig.Config) string {
	t.Helper()

	keys, err := gcrypto.LoadSigningKeys(cfg.Authentifications["self"].Local)
	if err != nil {
		t.Fatalf("LoadSigningKeys: %v", err)
	}

	token, err := gcrypto.MintSelfJWT(keys[0], "bootstrap", []string{middleware.SysadminGroupFor(testAppConfig().AppPlatform)}, time.Hour)
	if err != nil {
		t.Fatalf("MintSelfJWT: %v", err)
	}
	return token
}

func TestBuildRejectsUnknownFieldsOnWrongResourceEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := testKayraConfig(t)
	engine, err := Build(testAppConfig(), cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	token := mintSysadminToken(t, cfg)

	// A Role-shaped body (has "rules", no "authorization") posted to the
	// Group endpoint must now be rejected outright instead of silently
	// dropping "rules" and returning a Group with authorization: null —
	// the bug report this guards against.
	body := []byte(`{"name":"thetenant-role-sysadmin","description":"default role for sysadmin","metadata":{"namespace":"thetenant","region":"eu-west-1","platform":"sandbox"},"rules":[{"apis":["compute.infrapi.io"],"resources":["*"],"verbs":["*"]}]}`)

	req := httptest.NewRequest(http.MethodPost, "/apis/authorization.infrapi.io/v1/clustergroups", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf(`status = %d, want 400 (unknown field "rules" rejected), body: %s`, w.Code, w.Body.String())
	}

	// The matching correctly-shaped Role payload on the right endpoint
	// must still succeed.
	req = httptest.NewRequest(http.MethodPost, "/apis/authorization.infrapi.io/v1/clusterroles", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create role: status %d, body %s", w.Code, w.Body.String())
	}
}

// TestUserinfoSupportsGetAndPost confirms /oauth2/userinfo answers both
// methods the OIDC spec allows (GET MUST, POST MAY) — not just POST,
// which is all many clients default to but real OIDC providers (and the
// spec) also expect GET to work.
func TestUserinfoSupportsGetAndPost(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := testKayraConfig(t)
	engine, err := Build(testAppConfig(), cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	token := mintSysadminToken(t, cfg)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req := httptest.NewRequest(method, "/oauth2/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("%s /oauth2/userinfo: status %d, body %s", method, w.Code, w.Body.String())
		}
		if !bytes.Contains(w.Body.Bytes(), []byte(`"sub":"bootstrap"`)) {
			t.Fatalf("%s /oauth2/userinfo: body %s, want sub=bootstrap", method, w.Body.String())
		}
	}
}

// TestAuthorizeCheckRoute confirms the RBAC decision endpoint lives at
// /apis/authorization.infrapi.io/v1/check and that, before any RBAC
// rule is consulted, it refuses a namespace that doesn't exist (see
// catalog.Repository.CheckNamespace, wired in Build).
func TestAuthorizeCheckRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := testKayraConfig(t)
	engine, err := Build(testAppConfig(), cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	token := mintSysadminToken(t, cfg)

	body := []byte(`{"namespace":"core","api":"compute.infrapi.io","resource":"vm","verb":"list"}`)
	req := httptest.NewRequest(http.MethodPost, "/apis/authorization.infrapi.io/v1/check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body: %s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`namespace \"core\" not found`)) {
		t.Fatalf("body = %s, want namespace not found", w.Body.String())
	}
}

// TestUnknownRouteIsProblemDetail confirms an unknown path gets the
// same infrapi/lib problem+json body as every other error, not gin's
// plain-text "404 page not found".
func TestUnknownRouteIsProblemDetail(t *testing.T) {
	gin.SetMode(gin.TestMode)

	engine, err := Build(testAppConfig(), testKayraConfig(t))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/apis/nope.infrapi.io/v1/things", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want application/problem+json; body %s", ct, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"origin":"apiserver.NoRoute"`)) {
		t.Fatalf("body %s, want origin apiserver.NoRoute", w.Body.String())
	}
}

// TestDiscoveryListsBuiltinGroups confirms GET /apis derives Kayra's own
// groups from its live route table, scoped (namespaced or not) and with
// verbs exactly as the routes define them.
func TestDiscoveryListsBuiltinGroups(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := testKayraConfig(t)
	engine, err := Build(testAppConfig(), cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/apis", nil)
	req.Header.Set("Authorization", "Bearer "+mintSysadminToken(t, cfg))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /apis: status %d, body %s", w.Code, w.Body.String())
	}

	var groups []catalog.DiscoveryGroup
	if err := json.Unmarshal(w.Body.Bytes(), &groups); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	find := func(api, name string, namespaced bool) *catalog.ApiResource {
		for _, g := range groups {
			if g.Api != api || !g.Builtin {
				continue
			}
			for i, r := range g.Resources {
				if r.Name == name && r.Namespaced == namespaced {
					return &g.Resources[i]
				}
			}
		}
		return nil
	}
	for _, tc := range []struct {
		api, name  string
		namespaced bool
		verbs      string
	}{
		{"system.infrapi.io", "namespaces", false, "create,delete,get,list,update"},
		{"catalog.infrapi.io", "apiregistrations", false, "create,delete,get,list,update"},
		{"catalog.infrapi.io", "subscriptions", true, "create,delete,get,list,update"},
		{"authorization.infrapi.io", "clusterroles", false, "create,delete,get,list,update"},
		{"authorization.infrapi.io", "roles", true, "create,delete,get,list,update"},
	} {
		r := find(tc.api, tc.name, tc.namespaced)
		if r == nil {
			t.Errorf("GET /apis: no %s %q (namespaced=%v) in %s", tc.api, tc.name, tc.namespaced, w.Body.String())
			continue
		}
		if got := strings.Join(r.Verbs, ","); got != tc.verbs {
			t.Errorf("%s %s verbs = %s, want %s", tc.api, tc.name, got, tc.verbs)
		}
	}

	// Unauthenticated: refused like every other gated route.
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/apis", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("GET /apis without a token: status %d, want 401", w.Code)
	}
}

// TestOperationalEndpointsPerGroup confirms infrapi/lib's own -/
// endpoints are served under each of Kayra's groups, about that group's
// routes, without a token, and no longer at the root.
func TestOperationalEndpointsPerGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)

	engine, err := Build(testAppConfig(), testKayraConfig(t))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	want := []string{"/apis/system.infrapi.io/v1", "/apis/catalog.infrapi.io/v1", "/apis/authorization.infrapi.io/v1"}
	if got := Roots(); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("Roots = %v, want %v", got, want)
	}
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}
	for _, root := range want {
		for _, p := range []string{"/-/healthz", "/-/readyz", "/-/metrics", "/-/metadata", "/-/openapi.json", "/-/docs"} {
			if w := get(root + p); w.Code != http.StatusOK {
				t.Errorf("GET %s%s without a token: status %d, want 200", root, p, w.Code)
			}
		}
	}
	if w := get("/-/healthz"); w.Code != http.StatusNotFound {
		t.Errorf("GET /-/healthz: status %d, want 404", w.Code)
	}

	// each group's specification describes its own routes
	var spec struct {
		Paths map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(get("/apis/catalog.infrapi.io/v1/-/openapi.json").Body.Bytes(), &spec); err != nil {
		t.Fatalf("catalog spec: %v", err)
	}
	for p := range spec.Paths {
		if !strings.HasPrefix(p, "/apis/catalog.infrapi.io/v1/") {
			t.Errorf("catalog spec lists %s", p)
		}
	}
	if _, ok := spec.Paths["/apis/catalog.infrapi.io/v1/apiregistrations"]; !ok {
		t.Errorf("catalog spec misses apiregistrations: %v", spec.Paths)
	}
}

// TestAPIIndexListsKayraGroups confirms /.well-known/api.json lists
// Kayra's three groups, system first, without a token.
func TestAPIIndexListsKayraGroups(t *testing.T) {
	gin.SetMode(gin.TestMode)

	engine, err := Build(testAppConfig(), testKayraConfig(t))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/api.json", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	var idx struct {
		Groups []struct {
			Name, API, Version string
			Primary            bool
		} `json:"groups"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &idx); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	var got []string
	for _, g := range idx.Groups {
		got = append(got, g.Name+"="+g.API+"/"+g.Version)
	}
	want := "system=system.infrapi.io/v1 catalog=catalog.infrapi.io/v1 authorization=authorization.infrapi.io/v1"
	if strings.Join(got, " ") != want || !idx.Groups[0].Primary {
		t.Fatalf("groups = %v, want %s, system primary", got, want)
	}
}

// The cluster routes are decided on the cluster RBAC: the bootstrap
// token, a sysadmin's, creates a namespace; a token whose groups no
// binding names is refused.
func TestBuildClusterRoutesAreClusterRBAC(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := testKayraConfig(t)
	engine, err := Build(testAppConfig(), cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	keys, err := gcrypto.LoadSigningKeys(cfg.Authentifications["self"].Local)
	if err != nil {
		t.Fatal(err)
	}
	nobody, err := gcrypto.MintSelfJWT(keys[0], "nobody", []string{"sandbox-nobody"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		token  string
		status int
	}{{nobody, http.StatusForbidden}, {mintSysadminToken(t, cfg), http.StatusCreated}} {
		req := httptest.NewRequest(http.MethodPost, "/apis/system.infrapi.io/v1/namespaces", bytes.NewReader([]byte(`{"name":"thetenant"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.token)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		if w.Code != c.status {
			t.Errorf("status %d, body %s, want %d", w.Code, w.Body.String(), c.status)
		}
	}
}

// Reading the namespaces: a sysadmin sees every one; anyone else lists
// the ones they are in, and gets them, whatever their roles there.
func TestNamespacesReadByMembers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := testKayraConfig(t)
	engine, err := Build(testAppConfig(), cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	keys, err := gcrypto.LoadSigningKeys(cfg.Authentifications["self"].Local)
	if err != nil {
		t.Fatal(err)
	}
	nobody, err := gcrypto.MintSelfJWT(keys[0], "nobody", []string{"sandbox-nobody"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	root := mintSysadminToken(t, cfg)
	do := func(token, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		return w
	}
	const nss = "/apis/system.infrapi.io/v1/namespaces"
	for _, ns := range []string{"mine", "theirs"} {
		if w := do(root, http.MethodPost, nss, `{"name":"`+ns+`"}`); w.Code != http.StatusCreated {
			t.Fatalf("namespace %s: %d %s", ns, w.Code, w.Body.String())
		}
	}
	// nobody is in mine: a cluster group scoped to it names their group
	group := `{"name":"mine-admins","metadata":{"namespace":"mine","region":"eu-west-1","platform":"sandbox"},"groups":["sandbox-nobody"]}`
	if w := do(root, http.MethodPost, "/apis/authorization.infrapi.io/v1/clustergroups", group); w.Code != http.StatusCreated {
		t.Fatalf("cluster group: %d %s", w.Code, w.Body.String())
	}
	names := func(token string) string {
		t.Helper()
		w := do(token, http.MethodGet, nss, "")
		var list []struct{ Name string }
		if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || w.Code != http.StatusOK {
			t.Fatalf("list: %d %s", w.Code, w.Body.String())
		}
		var out []string
		for _, n := range list {
			out = append(out, n.Name)
		}
		slices.Sort(out)
		return strings.Join(out, " ")
	}
	if got := names(root); got != "mine theirs" {
		t.Errorf("the sysadmin's: %q", got)
	}
	if got := names(nobody); got != "mine" {
		t.Errorf("nobody's: %q", got)
	}
	for _, c := range []struct {
		token, method, path, body string
		status                    int
	}{
		{nobody, http.MethodGet, nss + "/mine", "", http.StatusOK},
		{nobody, http.MethodGet, nss + "/theirs", "", http.StatusForbidden},
		{nobody, http.MethodGet, nss + "/nowhere", "", http.StatusNotFound},
		{nobody, http.MethodPost, nss, `{"name":"x"}`, http.StatusForbidden},
		{nobody, http.MethodDelete, nss + "/mine", "", http.StatusForbidden},
		{root, http.MethodGet, nss + "/theirs", "", http.StatusOK},
		{"", http.MethodGet, nss, "", http.StatusUnauthorized},
	} {
		if w := do(c.token, c.method, c.path, c.body); w.Code != c.status {
			t.Errorf("%s %s: %d %s, want %d", c.method, c.path, w.Code, w.Body.String(), c.status)
		}
	}
	// /check agrees: can-i list namespaces, get them, not create them
	for verb, want := range map[string]bool{"list": true, "get": true, "create": false} {
		w := do(nobody, http.MethodPost, "/apis/authorization.infrapi.io/v1/check", `{"api":"system.infrapi.io","resource":"namespaces","verb":"`+verb+`"}`)
		var r struct{ Allowed bool }
		if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil || r.Allowed != want {
			t.Errorf("check %s: %d %s, want %v", verb, w.Code, w.Body.String(), want)
		}
	}
}
