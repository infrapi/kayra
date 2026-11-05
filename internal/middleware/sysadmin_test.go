package middleware

import (
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
	"github.com/golang-jwt/jwt/v5"

	"github.com/infrapi/kayra/internal/authz"
	"github.com/infrapi/kayra/internal/config"
	gcrypto "github.com/infrapi/kayra/internal/crypto"
	"github.com/infrapi/kayra/internal/oidc"
	"github.com/infrapi/kayra/internal/store"
)

const testPlatform = "sandbox"

func newSysadminTestGinContext(t *testing.T, authHeader string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/apis/authorization.example.com/v1/clustergroups", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	c.Request = req
	return c, w
}

// newLocalSysadminAuthenticator builds an Authenticator wired to a
// self-signed "self" provider whose authorizations.dev entry is a real
// (non-claims) backend — a local YAML user fixture — so a self-signed
// JWT's groups come from a live lookup by its "sub", exactly like any
// other non-claims-backed token SysadminGate now resolves the same way
// Authenticator.Middleware would. fixtureGroups is what the fixture
// resolves "bootstrap" to; it has nothing to do with whatever groups a
// caller might try to assert directly in the JWT itself.
func newLocalSysadminAuthenticator(t *testing.T, fixtureGroups []string) (*Authenticator, gcrypto.SigningKey) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	secret := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}))
	key := gcrypto.SigningKey{Kid: "k1", Algorithm: "RS256", Issuer: true, Private: priv, Public: &priv.PublicKey}

	usersPath := filepath.Join(t.TempDir(), "users.yaml")
	groupsYAML := ""
	for _, g := range fixtureGroups {
		groupsYAML += "      - " + g + "\n"
	}
	fixture := "users:\n  - id: bootstrap\n    groups:\n" + groupsYAML
	if err := os.WriteFile(usersPath, []byte(fixture), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := &config.Config{
		Authentifications: map[string]config.AuthProvider{
			"self": {
				Authorization: "dev",
				Local: []config.LocalSigningKey{
					{Enabled: true, Algorithm: "RS256", Issuer: true, Kid: key.Kid, Secret: secret},
				},
			},
		},
		Authorizations: map[string]config.AuthorizationBackend{
			"dev": {Local: &config.LocalAuthzConfig{Path: usersPath}},
		},
	}

	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	storeKeys := store.NewKeys("")

	m, err := oidc.NewManager(s, storeKeys, cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	backend, err := authz.New(cfg.Authorizations["dev"])
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}

	patPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	return &Authenticator{
		Manager:    m,
		Config:     cfg,
		Backends:   map[string]*authz.Cached{"dev": authz.NewCached(backend, s, storeKeys, "dev")},
		Store:      s,
		Keys:       storeKeys,
		PatKey:     patPriv,
		DefaultTTL: time.Hour,
	}, key
}

func TestSysadminGroupForRendersPlatformTemplate(t *testing.T) {
	if got, want := SysadminGroupFor("sandbox"), "sandbox-core-sysadmin"; got != want {
		t.Fatalf("SysadminGroupFor(sandbox) = %q, want %q", got, want)
	}
	if got, want := SysadminGroupFor("prod"), "prod-core-sysadmin"; got != want {
		t.Fatalf("SysadminGroupFor(prod) = %q, want %q", got, want)
	}
}

// TestSysadminGateAcceptsValidToken confirms a self-signed JWT whose
// "sub" resolves (via the live local-authz fixture, not the JWT's own
// claims) to the required group passes.
func TestSysadminGateAcceptsValidToken(t *testing.T) {
	requiredGroup := SysadminGroupFor(testPlatform)
	auth, key := newLocalSysadminAuthenticator(t, []string{"sandbox-infra-apps", requiredGroup, "sandbox-sre-sysadmin"})

	token, err := gcrypto.MintSelfJWT(key, "bootstrap", nil, time.Hour)
	if err != nil {
		t.Fatalf("MintSelfJWT: %v", err)
	}

	c, w := newSysadminTestGinContext(t, "Bearer "+token)
	handler := SysadminGate(auth, []string{requiredGroup})
	handler(c)

	if c.IsAborted() {
		t.Fatalf("request should not be aborted, body %s", w.Body.String())
	}

	ac, ok := GetAuth(c)
	if !ok {
		t.Fatalf("GetAuth: expected AuthContext to be set")
	}
	if len(ac.Groups) != 3 {
		t.Fatalf("AuthContext.Groups = %v, want all 3 fixture-resolved groups", ac.Groups)
	}
}

func TestSysadminGateRejectsMissingGroup(t *testing.T) {
	auth, key := newLocalSysadminAuthenticator(t, []string{"sandbox-apps-only"})

	token, err := gcrypto.MintSelfJWT(key, "bootstrap", nil, time.Hour)
	if err != nil {
		t.Fatalf("MintSelfJWT: %v", err)
	}

	c, w := newSysadminTestGinContext(t, "Bearer "+token)
	handler := SysadminGate(auth, []string{SysadminGroupFor(testPlatform)})
	handler(c)

	if w.Code != http.StatusForbidden {
		t.Fatalf("response code = %d, want 403", w.Code)
	}
	if !c.IsAborted() {
		t.Fatalf("request should be aborted")
	}
}

// TestSysadminGateAcceptsRemoteProviderToken is the fix for the bug a
// real Okta login used to hit: SysadminGate now authenticates exactly
// the way Authenticator.Middleware does for any other endpoint, so a
// remote, claims-backed provider's token (never a self-signed local
// JWT at all) satisfies it too, as long as its resolved groups include
// a configured sysadmin group.
func TestSysadminGateAcceptsRemoteProviderToken(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	srv := startFakeOktaProvider(t, "test-kid", &priv.PublicKey)
	auth, _, _, _ := newClaimsTestAuthenticator(t, srv)

	now := time.Now()
	token := signClaimsTestToken(t, priv, "test-kid", jwt.MapClaims{
		"sub":      "jdoe",
		"MemberOf": []string{SysadminGroupFor(testPlatform), "sandbox-sre-sysadmin"},
		"iat":      now.Unix(),
		"exp":      now.Add(time.Hour).Unix(),
	})

	c, w := newSysadminTestGinContext(t, "Bearer "+token)
	handler := SysadminGate(auth, []string{SysadminGroupFor(testPlatform)})
	handler(c)

	if c.IsAborted() {
		t.Fatalf("request should not be aborted, body %s", w.Body.String())
	}

	ac, ok := GetAuth(c)
	if !ok {
		t.Fatalf("GetAuth: expected AuthContext to be set")
	}
	if ac.UserID != "jdoe" {
		t.Fatalf("UserID = %q, want jdoe", ac.UserID)
	}
}

// TestSysadminGateUsesConfiguredGroupsNotTemplate confirms requiredGroups
// is whatever config.SysadminConfig.Groups says — not hardcoded to
// "$platform-core-sysadmin" — by requiring a group that doesn't match
// that template at all.
func TestSysadminGateUsesConfiguredGroupsNotTemplate(t *testing.T) {
	auth, key := newLocalSysadminAuthenticator(t, []string{"custom-admins"})

	token, err := gcrypto.MintSelfJWT(key, "bootstrap", nil, time.Hour)
	if err != nil {
		t.Fatalf("MintSelfJWT: %v", err)
	}

	c, w := newSysadminTestGinContext(t, "Bearer "+token)
	handler := SysadminGate(auth, []string{"custom-admins"})
	handler(c)

	if c.IsAborted() {
		t.Fatalf("request should not be aborted, body %s", w.Body.String())
	}
}

func TestSysadminGateRejectsUnknownKid(t *testing.T) {
	auth, _ := newLocalSysadminAuthenticator(t, []string{SysadminGroupFor(testPlatform)})

	other := gcrypto.SigningKey{Kid: "other-kid", Algorithm: "RS256", Issuer: true}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	other.Private, other.Public = priv, &priv.PublicKey

	token, err := gcrypto.MintSelfJWT(other, "bootstrap", nil, time.Hour)
	if err != nil {
		t.Fatalf("MintSelfJWT: %v", err)
	}

	c, w := newSysadminTestGinContext(t, "Bearer "+token)
	handler := SysadminGate(auth, []string{SysadminGroupFor(testPlatform)})
	handler(c)

	// An unverifiable token (no provider owns this kid) fails
	// authentication itself — 401, same as Authenticator.Middleware —
	// not 403 (which means "authenticated, but missing the group").
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("response code = %d, want 401", w.Code)
	}
}
