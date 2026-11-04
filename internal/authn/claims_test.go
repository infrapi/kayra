package authn

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/infrapi/kayra/internal/config"
)

// startFakeUserinfoProvider serves a minimal discovery document plus a
// userinfo endpoint answering body — just what ResolveGroups/
// ResolveAttributes need for their "userinfo_endpoint" path (no JWKS,
// unlike oidc's own test fixture, since nothing here verifies a token).
// hits counts every call the userinfo endpoint itself receives, so a
// caller can confirm it was fetched only once across several
// ResolveUserID/ResolveGroups/ResolveAttributes calls sharing one
// *Verified (see Verified.fetchUserinfo).
func startFakeUserinfoProvider(t *testing.T, body map[string]any) (srv *httptest.Server, hits *atomic.Int64) {
	t.Helper()

	hits = new(atomic.Int64)
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":            srv.URL,
			"jwks_uri":          srv.URL + "/keys",
			"userinfo_endpoint": srv.URL + "/userinfo",
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(body)
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, hits
}

func TestResolveGroupsFromToken(t *testing.T) {
	m, priv, kid := newTestManager(t)
	_ = m

	now := time.Now()
	tok := signTestToken(t, priv, kid, jwt.MapClaims{
		"sub":      "jdoe",
		"MemberOf": []string{"sandbox-core-sysadmin", "sandbox-sre-sysadmin"},
		"iat":      now.Unix(),
		"exp":      now.Add(time.Hour).Unix(),
	})
	v, err := Verify(m, tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	groups, err := ResolveGroups(v, "token", "MemberOf", "", "", "")
	if err != nil {
		t.Fatalf("ResolveGroups: %v", err)
	}
	if len(groups) != 2 || groups[0] != "sandbox-core-sysadmin" || groups[1] != "sandbox-sre-sysadmin" {
		t.Fatalf("ResolveGroups = %v, want [sandbox-core-sysadmin sandbox-sre-sysadmin]", groups)
	}
}

// TestResolveGroupsFromTokenWithFilter confirms groups_filter applies
// independently to each element exactly like an LDAP member_regex does
// to a real memberOf value: a non-matching element is dropped, a
// matching one contributes its first capture group.
func TestResolveGroupsFromTokenWithFilter(t *testing.T) {
	m, priv, kid := newTestManager(t)
	_ = m

	now := time.Now()
	tok := signTestToken(t, priv, kid, jwt.MapClaims{
		"sub": "jdoe",
		"MemberOf": []string{
			"sandbox-core-sysadmin",
			"app-netbox-user", // doesn't match the sandbox-* filter below
			"sandbox-sre-apps",
		},
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})
	v, err := Verify(m, tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	groups, err := ResolveGroups(v, "token", "MemberOf", `^(sandbox-\w+-\w+)$`, "", "")
	if err != nil {
		t.Fatalf("ResolveGroups: %v", err)
	}
	if len(groups) != 2 || groups[0] != "sandbox-core-sysadmin" || groups[1] != "sandbox-sre-apps" {
		t.Fatalf("ResolveGroups = %v, want [sandbox-core-sysadmin sandbox-sre-apps] (app-netbox-user dropped)", groups)
	}
}

func TestResolveGroupsRejectsMissingField(t *testing.T) {
	m, priv, kid := newTestManager(t)
	_ = m

	now := time.Now()
	tok := signTestToken(t, priv, kid, jwt.MapClaims{
		"sub": "jdoe",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})
	v, err := Verify(m, tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if _, err := ResolveGroups(v, "token", "MemberOf", "", "", ""); err == nil {
		t.Fatalf("ResolveGroups: want error for a token with no MemberOf claim at all")
	}
}

func TestResolveGroupsRejectsNonListField(t *testing.T) {
	m, priv, kid := newTestManager(t)
	_ = m

	now := time.Now()
	tok := signTestToken(t, priv, kid, jwt.MapClaims{
		"sub":      "jdoe",
		"MemberOf": "not-a-list",
		"iat":      now.Unix(),
		"exp":      now.Add(time.Hour).Unix(),
	})
	v, err := Verify(m, tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if _, err := ResolveGroups(v, "token", "MemberOf", "", "", ""); err == nil {
		t.Fatalf("ResolveGroups: want error when the claim is not a list")
	}
}

func TestResolveGroupsFromUserinfoEndpoint(t *testing.T) {
	m, priv, kid := newTestManager(t)
	_ = m

	srv, _ := startFakeUserinfoProvider(t, map[string]any{
		"sub":      "jdoe",
		"MemberOf": []string{"sandbox-core-sysadmin"},
	})

	now := time.Now()
	tok := signTestToken(t, priv, kid, jwt.MapClaims{
		"sub": "jdoe",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})
	v, err := Verify(m, tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	groups, err := ResolveGroups(v, "userinfo_endpoint", "MemberOf", "", srv.URL+"/.well-known/openid-configuration", "")
	if err != nil {
		t.Fatalf("ResolveGroups: %v", err)
	}
	if len(groups) != 1 || groups[0] != "sandbox-core-sysadmin" {
		t.Fatalf("ResolveGroups = %v, want [sandbox-core-sysadmin]", groups)
	}
}

func TestResolveAttributesFromToken(t *testing.T) {
	m, priv, kid := newTestManager(t)
	_ = m

	now := time.Now()
	tok := signTestToken(t, priv, kid, jwt.MapClaims{
		"sub":            "jdoe",
		"email":          "jdoe@example.com",
		"employeeNumber": "W110441",
		"locale":         "en_US",
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
	})
	v, err := Verify(m, tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	attrs, err := ResolveAttributes(v, "token", map[string]string{
		"email":       "email",
		"employee_id": "employeeNumber",
		"missing":     "no_such_field",
	}, "", "")
	if err != nil {
		t.Fatalf("ResolveAttributes: %v", err)
	}
	if attrs["email"] != "jdoe@example.com" {
		t.Fatalf(`attrs["email"] = %q, want "jdoe@example.com"`, attrs["email"])
	}
	if attrs["employee_id"] != "W110441" {
		t.Fatalf(`attrs["employee_id"] = %q, want "W110441"`, attrs["employee_id"])
	}
	// a named field with no matching source data resolves to "" rather
	// than being omitted — same as a missing LDAP attribute would.
	if v, ok := attrs["missing"]; !ok || v != "" {
		t.Fatalf(`attrs["missing"] = %q (present=%v), want "" present`, v, ok)
	}
}

// TestUserinfoFetchedOnlyOncePerToken confirms ResolveUserID,
// ResolveGroups and ResolveAttributes share one cached fetch on v
// (Verified.fetchUserinfo) rather than each hitting the provider's
// userinfo endpoint independently — a claims-backed
// authorizations.<name> entry with from: userinfo_endpoint resolves
// both Groups and Attributes on top of the user_id's own
// userinfo_endpoint lookup, and that must cost exactly one HTTP call
// to the provider, not three, for the one already-verified token.
func TestUserinfoFetchedOnlyOncePerToken(t *testing.T) {
	m, priv, kid := newTestManager(t)
	_ = m

	srv, hits := startFakeUserinfoProvider(t, map[string]any{
		"sub":      "jdoe",
		"email":    "jdoe@example.com",
		"MemberOf": []string{"sandbox-core-sysadmin"},
	})
	discoveryURL := srv.URL + "/.well-known/openid-configuration"

	now := time.Now()
	tok := signTestToken(t, priv, kid, jwt.MapClaims{
		"sub": "jdoe",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})
	v, err := Verify(m, tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if _, err := ResolveUserID(v, config.UserIDConfig{From: "userinfo_endpoint", Field: "sub"}, discoveryURL, ""); err != nil {
		t.Fatalf("ResolveUserID: %v", err)
	}
	if _, err := ResolveGroups(v, "userinfo_endpoint", "MemberOf", "", discoveryURL, ""); err != nil {
		t.Fatalf("ResolveGroups: %v", err)
	}
	if _, err := ResolveAttributes(v, "userinfo_endpoint", map[string]string{"email": "email"}, discoveryURL, ""); err != nil {
		t.Fatalf("ResolveAttributes: %v", err)
	}

	if got := hits.Load(); got != 1 {
		t.Fatalf("userinfo endpoint hit %d times, want exactly 1 (shared across all three calls)", got)
	}
}
