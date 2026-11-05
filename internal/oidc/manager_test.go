package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/infrapi/kayra/internal/config"
	"github.com/infrapi/kayra/internal/store"
)

func encodePrivateKeyPEMForTest(priv *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}))
}

func startFakeProvider(t *testing.T, kid string, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":            srv.URL,
			"jwks_uri":          srv.URL + "/keys",
			"userinfo_endpoint": srv.URL + "/userinfo",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(JWKSet{Keys: []JWK{NewJWK("okta", kid, "RS256", pub)}})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"sub": "jdoe@example.com"})
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestManagerRefreshAndFindKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	srv := startFakeProvider(t, "test-kid", &priv.PublicKey)

	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer func() { _ = s.Close() }()
	keys := store.NewKeys("")

	cfg := &config.Config{
		Authentifications: map[string]config.AuthProvider{
			"okta": {
				Authorization: "idm",
				Remote: &config.RemoteAuthConfig{
					Enabled: true,
					URL:     srv.URL + "/.well-known/openid-configuration",
					UserID:  config.UserIDConfig{From: "token", Field: "sub"},
				},
			},
		},
	}

	m, err := NewManager(s, keys, cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Not cached yet: FindKey must trigger a refresh and succeed.
	provider, jwk, err := m.FindKey("test-kid")
	if err != nil {
		t.Fatalf("FindKey: %v", err)
	}
	if provider != "okta" {
		t.Fatalf("FindKey provider = %q, want okta", provider)
	}
	if jwk.Kid != "test-kid" {
		t.Fatalf("FindKey kid = %q, want test-kid", jwk.Kid)
	}

	// Unknown kid even after refresh must error.
	if _, _, err := m.FindKey("does-not-exist"); err == nil {
		t.Fatalf("FindKey: want error for unknown kid")
	}
}

func TestManagerAllKeysAggregatesLocalAndRemote(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	srv := startFakeProvider(t, "remote-kid", &priv.PublicKey)

	selfPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	selfPem := encodePrivateKeyPEMForTest(selfPriv)

	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer func() { _ = s.Close() }()
	keys := store.NewKeys("")

	cfg := &config.Config{
		Authentifications: map[string]config.AuthProvider{
			"okta": {
				Authorization: "idm",
				Remote: &config.RemoteAuthConfig{
					Enabled: true,
					URL:     srv.URL + "/.well-known/openid-configuration",
					UserID:  config.UserIDConfig{From: "token", Field: "sub"},
				},
			},
			"self": {
				Authorization: "dev",
				Local: []config.LocalSigningKey{
					{Enabled: true, Algorithm: "RS512", Kid: "self-kid", Issuer: true, Secret: selfPem},
				},
			},
		},
	}

	m, err := NewManager(s, keys, cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	all := m.AllKeys()
	if len(all) != 2 {
		t.Fatalf("AllKeys() = %d keys, want 2: %+v", len(all), all)
	}

	var sawRemote, sawLocal bool
	for _, k := range all {
		if k.Kid == "remote-kid" && k.InfraPIAuthProvider == "okta" {
			sawRemote = true
		}
		if k.Kid == "self-kid" && k.InfraPIAuthProvider == "self" {
			sawLocal = true
		}
	}
	if !sawRemote || !sawLocal {
		t.Fatalf("AllKeys() missing expected entries: %+v", all)
	}
}
