package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// startFakeOktaProvider serves a minimal discovery document and JWKS for
// kid/pub — just enough for oidc.Manager.FindKey to resolve a remote
// provider's signing key, mirroring oidc's own test fixture.
func startFakeOktaProvider(t *testing.T, kid string, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   srv.URL,
			"jwks_uri": srv.URL + "/keys",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(oidc.JWKSet{Keys: []oidc.JWK{oidc.NewJWK("okta", kid, "RS256", pub)}})
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func signClaimsTestToken(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}

// newClaimsTestAuthenticator builds an Authenticator wired to a single
// "okta" provider whose own authorizations.okta entry is claims-backed
// (groups/attributes resolved straight from the token, no LDAP at
// all) — Backends is deliberately empty, exactly as apiserver.Build
// leaves it for a claims-backed entry (see Build's own backends loop).
func newClaimsTestAuthenticator(t *testing.T, srv *httptest.Server) (*Authenticator, store.Store, store.Keys, *rsa.PrivateKey) {
	t.Helper()

	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	keys := store.NewKeys("")

	cfg := &config.Config{
		Authentifications: map[string]config.AuthProvider{
			"okta": {
				Authorization: "okta",
				Remote: &config.RemoteAuthConfig{
					Enabled: true,
					URL:     srv.URL + "/.well-known/openid-configuration",
					UserID:  config.UserIDConfig{From: "token", Field: "sub"},
				},
			},
		},
		Authorizations: map[string]config.AuthorizationBackend{
			"okta": {
				Claims: &config.ClaimsAuthzConfig{
					From:        "token",
					GroupsField: "MemberOf",
					UserAttributes: map[string]string{
						"email": "email",
					},
				},
			},
		},
	}

	m, err := oidc.NewManager(s, keys, cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	patPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	return &Authenticator{
		Manager:    m,
		Config:     cfg,
		Backends:   map[string]*authz.Cached{},
		Store:      s,
		Keys:       keys,
		PatKey:     patPriv,
		DefaultTTL: time.Hour,
	}, s, keys, patPriv
}

func newAuthTestGinContext(t *testing.T, authHeader string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/whoami", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	c.Request = req
	return c, w
}

// TestAuthenticatorResolvesGroupsFromClaimsNoLDAP confirms a caller
// authenticated against a claims-backed authorizations.<name> entry
// gets Groups/Attributes straight out of their own token's claims —
// never touching a.Backends (empty here, exactly as it would be for a
// real claims-backed entry — see apiserver.Build).
func TestAuthenticatorResolvesGroupsFromClaimsNoLDAP(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	srv := startFakeOktaProvider(t, "test-kid", &priv.PublicKey)
	auth, _, _, _ := newClaimsTestAuthenticator(t, srv)

	now := time.Now()
	tok := signClaimsTestToken(t, priv, "test-kid", jwt.MapClaims{
		"sub":      "jdoe",
		"email":    "jdoe@example.com",
		"MemberOf": []string{"sandbox-core-sysadmin", "sandbox-sre-sysadmin"},
		"iat":      now.Unix(),
		"exp":      now.Add(time.Hour).Unix(),
	})

	c, w := newAuthTestGinContext(t, "Bearer "+tok)
	auth.Middleware()(c)
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
	if len(ac.Groups) != 2 || ac.Groups[0] != "sandbox-core-sysadmin" || ac.Groups[1] != "sandbox-sre-sysadmin" {
		t.Fatalf("Groups = %v, want [sandbox-core-sysadmin sandbox-sre-sysadmin]", ac.Groups)
	}
	if ac.Attributes["email"] != "jdoe@example.com" {
		t.Fatalf(`Attributes["email"] = %q, want "jdoe@example.com"`, ac.Attributes["email"])
	}
}

// TestAuthenticatorPATUsesSnapshotForClaimsBackend confirms a PAT minted
// under a claims-backed authorization backend is resolved from its own
// SnapshotGroups/SnapshotAttributes, not a live lookup — there is no
// a.Backends entry for "okta" at all, so any attempt to use one would
// fail outright.
func TestAuthenticatorPATUsesSnapshotForClaimsBackend(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	srv := startFakeOktaProvider(t, "test-kid", &priv.PublicKey)
	auth, s, keys, patPriv := newClaimsTestAuthenticator(t, srv)

	record := gcrypto.PatRecord{
		UserID:             "jdoe",
		Authorization:      "okta",
		Provider:           "okta",
		CreatedAt:          time.Now().Unix(),
		SnapshotGroups:     []string{"sandbox-core-sysadmin"},
		SnapshotAttributes: map[string]string{"email": "jdoe@example.com"},
	}
	data, err := gcrypto.EncryptRecord(&patPriv.PublicKey, record)
	if err != nil {
		t.Fatalf("EncryptRecord: %v", err)
	}
	token, err := gcrypto.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if err := s.Put(keys.PatToken(gcrypto.HashToken(token)), data); err != nil {
		t.Fatalf("Put: %v", err)
	}

	c, w := newAuthTestGinContext(t, "Bearer "+token)
	auth.Middleware()(c)
	if c.IsAborted() {
		t.Fatalf("request should not be aborted, body %s", w.Body.String())
	}

	ac, ok := GetAuth(c)
	if !ok {
		t.Fatalf("GetAuth: expected AuthContext to be set")
	}
	if len(ac.Groups) != 1 || ac.Groups[0] != "sandbox-core-sysadmin" {
		t.Fatalf("Groups = %v, want the PAT's own snapshot [sandbox-core-sysadmin]", ac.Groups)
	}
	if ac.Attributes["email"] != "jdoe@example.com" {
		t.Fatalf(`Attributes["email"] = %q, want the PAT's own snapshot`, ac.Attributes["email"])
	}
}
