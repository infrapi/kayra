package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/infrapi/kayra/internal/config"
	"github.com/infrapi/kayra/internal/oidc"
	"github.com/infrapi/kayra/internal/store"
)

func pemEncodeRSAPrivateKey(priv *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}))
}

func newTestManager(t *testing.T) (*oidc.Manager, *rsa.PrivateKey, string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	secret := pemEncodeRSAPrivateKey(priv)
	cfg := &config.Config{
		Authentifications: map[string]config.AuthProvider{
			"self": {
				Authorization: "dev",
				Local: []config.LocalSigningKey{
					{Enabled: true, Algorithm: "RS256", Kid: "self-kid", Issuer: true, Secret: secret},
				},
			},
		},
	}

	m, err := oidc.NewManager(s, store.NewKeys(""), cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	return m, priv, "self-kid"
}

func signTestToken(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}

func TestVerifyAcceptsValidToken(t *testing.T) {
	m, priv, kid := newTestManager(t)

	now := time.Now()
	tok := signTestToken(t, priv, kid, jwt.MapClaims{
		"sub": "jdoe@example.com",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})

	v, err := Verify(m, tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.Provider != "self" {
		t.Fatalf("Provider = %q, want self", v.Provider)
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	m, priv, kid := newTestManager(t)

	now := time.Now()
	tok := signTestToken(t, priv, kid, jwt.MapClaims{
		"sub": "jdoe",
		"iat": now.Add(-2 * time.Hour).Unix(),
		"exp": now.Add(-time.Hour).Unix(),
	})

	if _, err := Verify(m, tok); err == nil {
		t.Fatalf("Verify: want error for expired token")
	}
}

func TestVerifyRejectsFutureIat(t *testing.T) {
	m, priv, kid := newTestManager(t)

	now := time.Now()
	tok := signTestToken(t, priv, kid, jwt.MapClaims{
		"sub": "jdoe",
		"iat": now.Add(time.Hour).Unix(),
		"exp": now.Add(2 * time.Hour).Unix(),
	})

	if _, err := Verify(m, tok); err == nil {
		t.Fatalf("Verify: want error for future iat")
	}
}

func TestVerifyRejectsUnknownKid(t *testing.T) {
	m, priv, _ := newTestManager(t)

	now := time.Now()
	tok := signTestToken(t, priv, "unknown-kid", jwt.MapClaims{
		"sub": "jdoe",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})

	if _, err := Verify(m, tok); err == nil {
		t.Fatalf("Verify: want error for unknown kid")
	}
}

func TestResolveUserIDFromTokenWithFilter(t *testing.T) {
	m, priv, kid := newTestManager(t)
	_ = m

	now := time.Now()
	tok := signTestToken(t, priv, kid, jwt.MapClaims{
		"sub": "jdoe@example.com",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})

	v, err := Verify(m, tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	id, err := ResolveUserID(v, config.UserIDConfig{From: "token", Field: "sub", Filter: `^([^@]+)@`}, "", "")
	if err != nil {
		t.Fatalf("ResolveUserID: %v", err)
	}
	if id != "jdoe" {
		t.Fatalf("ResolveUserID = %q, want jdoe", id)
	}
}
