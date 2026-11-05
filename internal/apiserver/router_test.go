package apiserver

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

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
	fixture := "users:\n  - id: bootstrap\n    groups: [sandbox-core-sysadmin]\n    attributes:\n      email: bootstrap@example.com\n"
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
// Build wires up behind middleware.SysadminGate.
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
	body := []byte(`{"name":"thetenant-role-sysadmin","description":"default role for sysadmin","metadata":{"namespace":"thetenant","region":"eu-west-1","platform":"sandbox"},"rules":[{"apis":["compute.example.com"],"resources":["*"],"verbs":["*"]}]}`)

	req := httptest.NewRequest(http.MethodPost, "/apis/authorization.example.com/v1/clustergroups", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf(`status = %d, want 400 (unknown field "rules" rejected), body: %s`, w.Code, w.Body.String())
	}

	// The matching correctly-shaped Role payload on the right endpoint
	// must still succeed.
	req = httptest.NewRequest(http.MethodPost, "/apis/authorization.example.com/v1/clusterroles", bytes.NewReader(body))
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
// /apis/authorization.example.com/v1/check and that, before any RBAC
// rule is consulted, it refuses a namespace that doesn't exist (see
// catalog.Repository.CheckSubscribedApi, wired in Build).
func TestAuthorizeCheckRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := testKayraConfig(t)
	engine, err := Build(testAppConfig(), cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	token := mintSysadminToken(t, cfg)

	body := []byte(`{"namespace":"core","api":"compute.example.com","resource":"vm","verb":"list"}`)
	req := httptest.NewRequest(http.MethodPost, "/apis/authorization.example.com/v1/check", bytes.NewReader(body))
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
