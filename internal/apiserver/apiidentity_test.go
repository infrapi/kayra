package apiserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// An API's own identity, end to end: its registration's identity (pinned
// keys, federated credentials), its token by client_credentials, what it
// may read of itself without any grant, what a group naming it in apis
// grants, and its token refused once its registration is gone.
func TestApiIdentity(t *testing.T) {
	r := newOAuth2Rig(t)
	root := mintSysadminToken(t, r.cfg)
	const (
		catalog = "/apis/catalog.infrapi.io/v1"
		authz   = "/apis/authorization.infrapi.io/v1"
		client  = "system:api:compute.infrapi.io"
		meta    = `"metadata":{"region":"eu-west-1","platform":"sandbox"}`
	)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	jwk := map[string]string{"kty": "EC", "crv": "P-256", "kid": "compute-1", "x": b64(key.X.FillBytes(make([]byte, 32))), "y": b64(key.Y.FillBytes(make([]byte, 32)))}
	register := func(name string, identity any) (int, map[string]any) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"name": name, "owner": "team", "identity": identity})
		return r.call(root, http.MethodPost, catalog+"/apiregistrations", string(body))
	}
	if code, out := register("compute.infrapi.io", map[string]any{"jwks": map[string]any{"keys": []any{jwk}}}); code != http.StatusCreated || out["uid"] == "" {
		t.Fatalf("register: %d %v", code, out)
	}
	if code, out := register("network.infrapi.io", nil); code != http.StatusCreated {
		t.Fatalf("register network: %d %v", code, out)
	}
	// posted again (app register): the same uid
	_, first := r.call(root, http.MethodGet, catalog+"/apiregistrations/compute.infrapi.io", "")
	register("compute.infrapi.io", map[string]any{"jwks": map[string]any{"keys": []any{jwk}}})
	if _, again := r.call(root, http.MethodGet, catalog+"/apiregistrations/compute.infrapi.io", ""); again["uid"] != first["uid"] {
		t.Fatalf("uid changed: %v, then %v", first["uid"], again["uid"])
	}

	assertion := func(sub string) string {
		t.Helper()
		now := time.Now()
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": sub, "sub": sub, "aud": r.kayra + "/oauth2/token",
			"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": rand.Text()})
		tok.Header["kid"] = "compute-1"
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	code, out := r.clientCredentials(client, assertion(client))
	if code != http.StatusOK {
		t.Fatalf("client_credentials: %d %v", code, out)
	}
	token := out["access_token"].(string)
	if code, info := r.call(token, http.MethodGet, "/oauth2/userinfo", ""); code != http.StatusOK || info["sub"] != client || info["kind"] != "api" {
		t.Fatalf("userinfo: %d %v", code, info)
	}
	// an API without identity gets no token
	if code, out := r.clientCredentials("system:api:network.infrapi.io", assertion("system:api:network.infrapi.io")); code != http.StatusUnauthorized {
		t.Errorf("no identity: %d %v", code, out)
	}

	// itself, without any grant: its registration and its status
	for path, want := range map[string]int{
		catalog + "/apiregistrations/compute.infrapi.io":        http.StatusOK,
		catalog + "/apiregistrations/compute.infrapi.io/status": http.StatusOK,
		catalog + "/apiregistrations/network.infrapi.io":        http.StatusForbidden,
		catalog + "/apiregistrations":                           http.StatusForbidden,
		authz + "/clustergroups":                                http.StatusForbidden,
	} {
		if code, out := r.call(token, http.MethodGet, path, ""); code != want {
			t.Errorf("GET %s: %d %v, want %d", path, code, out, want)
		}
	}
	check := func(body string) (bool, string) {
		t.Helper()
		code, out := r.call(token, http.MethodPost, authz+"/check", body)
		if code != http.StatusOK {
			t.Fatalf("check %s: %d %v", body, code, out)
		}
		reason, _ := out["reason"].(string)
		return out["allowed"] == true, reason
	}
	if ok, reason := check(`{"api":"catalog.infrapi.io","resource":"apiregistrations","verb":"get","name":"compute.infrapi.io"}`); !ok {
		t.Errorf("can-i get its registration: %s", reason)
	}
	if ok, _ := check(`{"api":"catalog.infrapi.io","resource":"apiregistrations","verb":"get","name":"network.infrapi.io"}`); ok {
		t.Error("can-i get another's registration")
	}

	// a cluster group naming it in apis: the cluster RBAC's rights
	for _, call := range []struct{ path, body string }{
		{authz + "/clustergroups", `{"name":"readers",` + meta + `,"apis":["compute.infrapi.io"]}`},
		{authz + "/clusterroles", `{"name":"reader",` + meta + `,"rules":[{"apis":["catalog.infrapi.io"],"resources":["apiregistrations"],"verbs":["list"]}]}`},
		{authz + "/clusterrolebindings", `{"name":"readers",` + meta + `,"role":"reader","groups":["readers"]}`},
	} {
		if code, out := r.call(root, http.MethodPost, call.path, call.body); code != http.StatusCreated {
			t.Fatalf("%s: %d %v", call.path, code, out)
		}
	}
	if code, out := r.call(token, http.MethodGet, catalog+"/apiregistrations", ""); code != http.StatusOK {
		t.Errorf("list, granted: %d %v", code, out)
	}
	for _, bad := range []string{
		`{"name":"x",` + meta + `,"apis":["*"]}`,
		`{"name":"x",` + meta + `,"apis":["compute"]}`,
		`{"name":"x",` + meta + `,"users":["system:api:compute.infrapi.io"]}`,
	} {
		if code, out := r.call(root, http.MethodPost, authz+"/clustergroups", bad); code != http.StatusBadRequest {
			t.Errorf("%s: %d %v", bad, code, out)
		}
	}

	// federated: its platform's token (a Kubernetes service account's)
	sub := "system:serviceaccount:compute:compute-api"
	if code, out := register("compute.infrapi.io", map[string]any{"federated_credentials": []any{
		map[string]any{"name": "k8s", "issuer": r.ci.srv.URL, "subject": sub},
	}}); code != http.StatusCreated {
		t.Fatalf("register federated: %d %v", code, out)
	}
	if code, out := r.clientCredentials(client, r.jobToken(jwt.MapClaims{"sub": sub})); code != http.StatusOK {
		t.Errorf("federated: %d %v", code, out)
	}
	if code, out := r.clientCredentials(client, r.jobToken(jwt.MapClaims{"sub": "system:serviceaccount:compute:other"})); code != http.StatusUnauthorized {
		t.Errorf("federated, another sub: %d %v", code, out)
	}

	// what an identity may be
	for _, bad := range []any{
		map[string]any{},
		map[string]any{"jwks_from": "url"},
		map[string]any{"jwks_from": "spec", "jwks": map[string]any{"keys": []any{jwk}}},
		map[string]any{"jwks": map[string]any{"keys": []any{map[string]string{"kty": "EC", "crv": "P-256", "x": jwk["x"], "y": jwk["y"], "d": "secret"}}}},
		map[string]any{"federated_credentials": []any{map[string]any{"name": "x", "issuer": "https://evil.example.com", "subject": "s"}}},
	} {
		if code, out := register("compute.infrapi.io", bad); code != http.StatusBadRequest {
			t.Errorf("identity %v: %d %v", bad, code, out)
		}
	}

	// its registration gone: its token refused, even once registered again
	if code, out := r.call(root, http.MethodDelete, catalog+"/apiregistrations/compute.infrapi.io", ""); code != http.StatusNoContent {
		t.Fatalf("delete: %d %v", code, out)
	}
	if code := r.userinfo(token); code != http.StatusUnauthorized {
		t.Errorf("deleted: %d", code)
	}
	register("compute.infrapi.io", map[string]any{"jwks": map[string]any{"keys": []any{jwk}}})
	if code := r.userinfo(token); code != http.StatusUnauthorized {
		t.Errorf("registered again: %d", code)
	}
}
