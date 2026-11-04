package tokenapi

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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

func TestCreateAndUsePAT(t *testing.T) {
	gin.SetMode(gin.TestMode)

	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer s.Close()
	keys := store.NewKeys("")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	backend := &fakeAuthzBackend{info: authz.UserInfo{
		ID:         "jdoe",
		Attributes: map[string]string{"email": "jdoe@example.com"},
		Groups:     []string{"tenant-group-apps"},
	}}
	cached := authz.NewCached(backend, s, keys, "idm")
	cfg := &gconfig.Config{Authorizations: map[string]gconfig.AuthorizationBackend{"idm": {}}}

	auth := &middleware.Authenticator{
		Config:   cfg,
		Backends: map[string]*authz.Cached{"idm": cached},
		Store:    s,
		Keys:     keys,
		PatKey:   priv,
	}

	engine := gin.New()
	// A fake "already authenticated" gate stands in for a real bearer-JWT
	// login, since this test only exercises PAT issuance and PAT reuse.
	fakeLoginGate := func(c *gin.Context) {
		c.Set("kayra.auth", &middleware.AuthContext{UserID: "jdoe", Authorization: "idm", Provider: "okta"})
	}
	RegisterRoutes(engine, fakeLoginGate, s, keys, &priv.PublicKey, cfg)

	engine.GET("/whoami", auth.Middleware(), func(c *gin.Context) {
		ac, _ := middleware.GetAuth(c)
		c.JSON(http.StatusOK, gin.H{"user_id": ac.UserID, "groups": ac.Groups})
	})

	// Issue the PAT.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create token: status %d, body %s", w.Code, w.Body.String())
	}

	var created struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !gcrypto.IsToken(created.Token) {
		t.Fatalf("created token %q does not look like a PAT", created.Token)
	}

	// Use the PAT against an unrelated authenticated route.
	req = httptest.NewRequest(http.MethodGet, "/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+created.Token)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("whoami with PAT: status %d, body %s", w.Code, w.Body.String())
	}

	var who struct {
		UserID string   `json:"user_id"`
		Groups []string `json:"groups"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &who); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if who.UserID != "jdoe" {
		t.Fatalf("UserID = %q, want jdoe", who.UserID)
	}
	if len(who.Groups) != 1 || who.Groups[0] != "tenant-group-apps" {
		t.Fatalf("Groups = %v, want [tenant-group-apps] (resolved live, not snapshotted)", who.Groups)
	}
}

// TestCreateAndUsePATSnapshotsGroupsForClaimsBackend confirms a PAT
// minted while authenticated via a claims-backed authorizations.<name>
// entry (Okta, say — no LDAP, no a.Backends entry at all) captures the
// caller's own already-resolved Groups/Attributes into the record at
// creation time, and that resolving the PAT later reads that snapshot
// back rather than attempting a live lookup that has nowhere to go.
func TestCreateAndUsePATSnapshotsGroupsForClaimsBackend(t *testing.T) {
	gin.SetMode(gin.TestMode)

	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer s.Close()
	keys := store.NewKeys("")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cfg := &gconfig.Config{
		Authorizations: map[string]gconfig.AuthorizationBackend{
			"okta": {Claims: &gconfig.ClaimsAuthzConfig{From: "token", GroupsField: "MemberOf"}},
		},
	}

	// Deliberately no "okta" entry: a claims-backed authorizations.<name>
	// never gets one (see apiserver.Build), so any attempt to use it
	// would fail outright — this test is only meaningful if resolving the
	// PAT below truly never reaches a.Backends.
	auth := &middleware.Authenticator{
		Config:   cfg,
		Backends: map[string]*authz.Cached{},
		Store:    s,
		Keys:     keys,
		PatKey:   priv,
	}

	engine := gin.New()
	fakeLoginGate := func(c *gin.Context) {
		c.Set("kayra.auth", &middleware.AuthContext{
			UserID: "jdoe", Authorization: "okta", Provider: "okta",
			Groups:     []string{"sandbox-core-sysadmin"},
			Attributes: map[string]string{"email": "jdoe@example.com"},
		})
	}
	RegisterRoutes(engine, fakeLoginGate, s, keys, &priv.PublicKey, cfg)

	engine.GET("/whoami", auth.Middleware(), func(c *gin.Context) {
		ac, _ := middleware.GetAuth(c)
		c.JSON(http.StatusOK, gin.H{"user_id": ac.UserID, "groups": ac.Groups})
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tokens", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create token: status %d, body %s", w.Code, w.Body.String())
	}

	var created struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	req = httptest.NewRequest(http.MethodGet, "/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+created.Token)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("whoami with PAT: status %d, body %s", w.Code, w.Body.String())
	}

	var who struct {
		UserID string   `json:"user_id"`
		Groups []string `json:"groups"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &who); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(who.Groups) != 1 || who.Groups[0] != "sandbox-core-sysadmin" {
		t.Fatalf("Groups = %v, want the snapshot [sandbox-core-sysadmin] (no live backend exists to re-resolve from)", who.Groups)
	}
}

func TestUnknownTokenRejected(t *testing.T) {
	gin.SetMode(gin.TestMode)

	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer s.Close()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	auth := &middleware.Authenticator{
		Backends: map[string]*authz.Cached{},
		Store:    s,
		Keys:     store.NewKeys(""),
		PatKey:   priv,
	}

	engine := gin.New()
	engine.GET("/whoami", auth.Middleware(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	fake, err := gcrypto.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+fake)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}
