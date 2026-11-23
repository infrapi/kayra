package apiserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// jobToken is a token of the CI issuer, as GitLab or GitHub hands a job.
func (r *oauth2Rig) jobToken(claims jwt.MapClaims) string {
	r.t.Helper()
	now := time.Now()
	base := jwt.MapClaims{"iss": r.ci.srv.URL, "aud": r.kayra, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": rand.Text()}
	for k, v := range claims {
		if v == nil {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, base)
	t.Header["kid"] = r.ci.kid
	signed, err := t.SignedString(r.ci.key)
	if err != nil {
		r.t.Fatal(err)
	}
	return signed
}

// clientCredentials asks the token endpoint for client's token.
func (r *oauth2Rig) clientCredentials(client, assertion string, resources ...string) (int, map[string]any) {
	r.t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {client},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {assertion}}
	for _, res := range resources {
		form.Add("resource", res)
	}
	resp, out := r.post("/oauth2/token", form)
	return resp.StatusCode, out
}

// client_credentials, end to end: a service account's own key
// (private_key_jwt) and its federated credentials (a CI job's token),
// what each refuses, and the token it gets.
func TestClientCredentials(t *testing.T) {
	r := newOAuth2Rig(t)
	root := mintSysadminToken(t, r.cfg)
	const (
		authz  = "/apis/authorization.infrapi.io/v1"
		sas    = authz + "/namespaces/core/serviceaccounts"
		meta   = `"metadata":{"namespace":"core","region":"eu-west-1","platform":"sandbox"}`
		client = "system:serviceaccount:core:deployer"
	)
	for _, call := range []struct{ path, body string }{
		{"/apis/system.infrapi.io/v1/namespaces", `{"name":"core"}`},
		{authz + "/clustergroups", `{"name":"core-admins",` + meta + `,"users":["bootstrap"]}`},
		{authz + "/clusterroles", `{"name":"core-admin",` + meta + `,"rules":[{"apis":["authorization.infrapi.io"],"resources":["*"],"verbs":["*"]}]}`},
		{authz + "/clusterrolebindings", `{"name":"core-admins",` + meta + `,"role":"core-admin","groups":["core-admins"]}`},
	} {
		if code, out := r.call(root, http.MethodPost, call.path, call.body); code != http.StatusCreated {
			t.Fatalf("%s: %d %v", call.path, code, out)
		}
	}

	// its own key, EC P-256, the public half in its jwks
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	jwk := map[string]string{"kty": "EC", "crv": "P-256", "kid": "ci-1", "x": b64(key.X.FillBytes(make([]byte, 32))), "y": b64(key.Y.FillBytes(make([]byte, 32)))}
	sa := map[string]any{"name": "deployer", "jwks": map[string]any{"keys": []any{jwk}}, "federated_credentials": []any{
		map[string]any{"name": "gitlab-main", "issuer": r.ci.srv.URL, "subject": "project_path:infra/compute:ref_type:branch:ref:main"},
		map[string]any{"name": "github-prod", "issuer": r.ci.srv.URL, "claims": map[string]string{"repository": "example/compute", "environment": "prod"}},
	}}
	body, _ := json.Marshal(sa)
	if code, out := r.call(root, http.MethodPost, sas, string(body)); code != http.StatusCreated {
		t.Fatalf("service account: %d %v", code, out)
	}

	own := func(claims jwt.MapClaims) string {
		t.Helper()
		now := time.Now()
		base := jwt.MapClaims{"iss": client, "sub": client, "aud": r.kayra + "/oauth2/token", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": rand.Text()}
		for k, v := range claims {
			if v == nil {
				delete(base, k)
			} else {
				base[k] = v
			}
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, base)
		tok.Header["kid"] = "ci-1"
		signed, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	ok := func(assertion string, resources ...string) string {
		t.Helper()
		code, out := r.clientCredentials(client, assertion, resources...)
		if code != http.StatusOK || out["token_type"] != "Bearer" || out["refresh_token"] != nil {
			t.Fatalf("client_credentials: %d %v", code, out)
		}
		return out["access_token"].(string)
	}
	refused := func(what string, code int, assertion string, want string) {
		t.Helper()
		got, out := r.clientCredentials(client, assertion)
		if got != code || !strings.Contains(out["error_description"].(string), want) {
			t.Errorf("%s: %d %v, want %d %q", what, got, out, code, want)
		}
	}

	// private_key_jwt: its token, a service account's
	assertion := own(nil)
	token := ok(assertion)
	code, info := r.call(token, http.MethodGet, "/oauth2/userinfo", "")
	if code != http.StatusOK || info["sub"] != client || info["kind"] != "serviceaccount" {
		t.Fatalf("its token: %d %v", code, info)
	}
	refused("the same assertion again", http.StatusUnauthorized, assertion, "used already")
	refused("aud another's", http.StatusUnauthorized, own(jwt.MapClaims{"aud": "https://elsewhere.example.com"}), "aud")
	refused("living an hour", http.StatusUnauthorized, own(jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()}), "more than 5m0s")
	refused("expired", http.StatusUnauthorized, own(jwt.MapClaims{"exp": time.Now().Add(-time.Hour).Unix()}), "expired")
	refused("no jti", http.StatusUnauthorized, own(jwt.MapClaims{"jti": nil}), "no jti")
	refused("sub another's", http.StatusUnauthorized, own(jwt.MapClaims{"sub": "system:serviceaccount:core:other"}), "not the client")
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	forged := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": client, "sub": client, "aud": r.kayra, "exp": time.Now().Add(time.Minute).Unix(), "jti": "x"})
	forged.Header["kid"] = "ci-1"
	signed, _ := forged.SignedString(other)
	refused("another key", http.StatusUnauthorized, signed, "signature")

	// federated: the CI job's token, by its subject or its claims
	job := r.jobToken(jwt.MapClaims{"sub": "project_path:infra/compute:ref_type:branch:ref:main"})
	ok(job)
	ok(job) // a job presents its token as often as it needs
	ok(r.jobToken(jwt.MapClaims{"sub": "repo:example/compute:environment:prod", "repository": "example/compute", "environment": "prod"}))
	refused("another branch", http.StatusUnauthorized, r.jobToken(jwt.MapClaims{"sub": "project_path:infra/compute:ref_type:branch:ref:dev"}), "none of the client's federated credentials")
	refused("a claim missing", http.StatusUnauthorized, r.jobToken(jwt.MapClaims{"repository": "example/compute"}), "none of the client's federated credentials")
	refused("aud not Kayra", http.StatusUnauthorized, r.jobToken(jwt.MapClaims{"sub": "project_path:infra/compute:ref_type:branch:ref:main", "aud": "https://gitlab.example.com"}), "none of the client's federated credentials")
	refused("expired", http.StatusUnauthorized, r.jobToken(jwt.MapClaims{"sub": "project_path:infra/compute:ref_type:branch:ref:main", "exp": time.Now().Add(-time.Hour).Unix()}), "expired")
	refused("an untrusted issuer", http.StatusUnauthorized, r.jobToken(jwt.MapClaims{"iss": "https://evil.example.com"}), "not one Kayra trusts")
	refused("signed by another", http.StatusUnauthorized, func() string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": r.ci.srv.URL, "aud": r.kayra, "sub": "project_path:infra/compute:ref_type:branch:ref:main", "exp": time.Now().Add(time.Minute).Unix()})
		tok.Header["kid"] = r.ci.kid
		s, _ := tok.SignedString(r.okta.key)
		return s
	}(), "verification")

	// the request itself
	if code, out := r.clientCredentials("system:serviceaccount:core:nobody", job); code != http.StatusUnauthorized || out["error"] != "invalid_client" {
		t.Errorf("an unknown service account: %d %v", code, out)
	}
	if code, out := r.clientCredentials("infrapi-cli", job); code != http.StatusUnauthorized {
		t.Errorf("a public client: %d %v", code, out)
	}
	if code, out := r.clientCredentials(client, r.jobToken(jwt.MapClaims{"sub": "project_path:infra/compute:ref_type:branch:ref:main"}), "https://elsewhere.example.com"); code != http.StatusBadRequest || out["error"] != "invalid_target" {
		t.Errorf("another resource: %d %v", code, out)
	}
	resp, out := r.post("/oauth2/token", url.Values{"grant_type": {"client_credentials"}, "client_id": {client}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no assertion: %d %v", resp.StatusCode, out)
	}

	// a credential of an untrusted issuer, a private key: refused
	for _, bad := range []string{
		`{"federated_credentials":[{"name":"x","issuer":"https://evil.example.com","subject":"s"}]}`,
		`{"federated_credentials":[{"name":"x","issuer":"` + r.ci.srv.URL + `"}]}`,
		`{"federated_credentials":[{"name":"x","issuer":"` + r.ci.srv.URL + `","subject":"a"},{"name":"x","issuer":"` + r.ci.srv.URL + `","subject":"b"}]}`,
		`{"jwks":{"keys":[{"kty":"EC","crv":"P-256","x":"` + jwk["x"] + `","y":"` + jwk["y"] + `","d":"secret"}]}}`,
		`{"jwks":{"keys":[{"kty":"oct","k":"x"}]}}`,
	} {
		if code, out := r.call(root, http.MethodPut, sas+"/deployer", bad); code != http.StatusBadRequest {
			t.Errorf("%s: %d %v", bad, code, out)
		}
	}

	meta2 := r.get(r.kayra + "/.well-known/oauth-authorization-server")
	if meta2.StatusCode != http.StatusOK {
		t.Fatal(meta2.StatusCode)
	}
	_, md := r.call("", http.MethodGet, "/.well-known/oauth-authorization-server", "")
	if !strings.Contains(strings.Join(anyStrings(md["grant_types_supported"]), " "), "client_credentials") ||
		!strings.Contains(strings.Join(anyStrings(md["token_endpoint_auth_methods_supported"]), " "), "private_key_jwt") {
		t.Errorf("metadata: %v", md)
	}
}

func anyStrings(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}
