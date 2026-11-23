package apiserver

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	gcrypto "github.com/infrapi/kayra/internal/crypto"
)

// call sends body to path with token, and decodes the JSON answer.
func (r *oauth2Rig) call(token, method, path, body string) (int, map[string]any) {
	r.t.Helper()
	req, _ := http.NewRequest(method, r.kayra+path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	if out == nil {
		out = map[string]any{"raw": string(data)}
	}
	return resp.StatusCode, out
}

// A namespace's service account, end to end on a real server: created by
// its namespace's admin, its token from the authorization server's
// signer, resolved by the authenticator from the store, a member of its
// namespace only, refused once deleted, even when recreated.
func TestServiceAccounts(t *testing.T) {
	r := newOAuth2Rig(t)
	root := mintSysadminToken(t, r.cfg)
	const (
		authz = "/apis/authorization.infrapi.io/v1"
		sas   = authz + "/namespaces/core/serviceaccounts"
		check = authz + "/check"
		meta  = `"metadata":{"namespace":"core","region":"eu-west-1","platform":"sandbox"}`
	)
	// must(r.call(...))(want, what): the answer, a failure unless want
	must := func(code int, out map[string]any) func(int, string) map[string]any {
		return func(want int, what string) map[string]any {
			t.Helper()
			if code != want {
				t.Fatalf("%s: %d %v, want %d", what, code, out, want)
			}
			return out
		}
	}
	for _, ns := range []string{"core", "other"} {
		must(r.call(root, http.MethodPost, "/apis/system.infrapi.io/v1/namespaces", `{"name":"`+ns+`"}`))(http.StatusCreated, ns)
	}
	// bootstrap is core's admin: a cluster group scoped to it
	must(r.call(root, http.MethodPost, authz+"/clustergroups", `{"name":"core-admins",`+meta+`,"users":["bootstrap"]}`))(http.StatusCreated, "cluster group")
	must(r.call(root, http.MethodPost, authz+"/clusterroles", `{"name":"core-admin",`+meta+`,"rules":[{"apis":["authorization.infrapi.io"],"resources":["*"],"verbs":["*"]}]}`))(http.StatusCreated, "cluster role")
	must(r.call(root, http.MethodPost, authz+"/clusterrolebindings", `{"name":"core-admins",`+meta+`,"role":"core-admin","groups":["core-admins"]}`))(http.StatusCreated, "cluster binding")

	sa := must(r.call(root, http.MethodPost, sas, `{"name":"deployer","description":"the CI"}`))(http.StatusCreated, "service account")
	must(r.call(root, http.MethodPost, authz+"/namespaces/core/groups", `{"name":"ci",`+meta+`,"serviceaccounts":["deployer"]}`))(http.StatusCreated, "group")

	tok := must(r.call(root, http.MethodPost, sas+"/deployer/token", `{"expires_in":"10m"}`))(http.StatusCreated, "token")
	token, _ := tok["token"].(string)
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "system:serviceaccount:core:deployer" || claims["kind"] != "serviceaccount" || claims["uid"] != sa["uid"] || claims["iss"] != r.kayra {
		t.Fatalf("claims = %v", claims)
	}
	if exp, _ := claims.GetExpirationTime(); time.Until(exp.Time) > 11*time.Minute {
		t.Fatalf("exp %s: not 10 minutes", exp)
	}
	if aud, _ := claims.GetAudience(); len(aud) != 1 || aud[0] != r.kayra {
		t.Fatalf("aud = %v, want Kayra's", aud)
	}
	must(r.call(root, http.MethodPost, sas+"/deployer/token", `{"expires_in":"25h"}`))(http.StatusBadRequest, "25h")
	must(r.call(root, http.MethodPost, sas+"/deployer/token", `{"audience":["https://elsewhere.example.com"]}`))(http.StatusBadRequest, "another audience")

	// who it is
	info := must(r.call(token, http.MethodGet, "/oauth2/userinfo", ""))(http.StatusOK, "userinfo")
	if info["sub"] != "system:serviceaccount:core:deployer" || info["kind"] != "serviceaccount" || info["client_id"] != "system:serviceaccount:core:deployer" {
		t.Fatalf("userinfo = %v", info)
	}
	if g, _ := info["groups"].([]any); len(g) != 2 || g[1] != "system:serviceaccounts:core" {
		t.Fatalf("groups = %v", info["groups"])
	}

	// a member of core: /check gets past membership to the api (not
	// registered here); of other, not; nothing cluster-scoped; no RBAC
	// to manage, not even its own namespace's
	out := must(r.call(token, http.MethodPost, check, `{"namespace":"core","api":"compute.infrapi.io","resource":"vms","verb":"list"}`))(http.StatusNotFound, "check in core")
	if !strings.Contains(out["detail"].(string), "not registered") {
		t.Fatalf("check in core: %v, want past the membership", out)
	}
	out = must(r.call(token, http.MethodPost, check, `{"namespace":"other","api":"compute.infrapi.io","resource":"vms","verb":"list"}`))(http.StatusOK, "check in other")
	if out["allowed"] != false || !strings.Contains(out["reason"].(string), "not a member") {
		t.Fatalf("check in other: %v", out)
	}
	out = must(r.call(token, http.MethodPost, check, `{"api":"system.infrapi.io","resource":"namespaces","verb":"create"}`))(http.StatusOK, "check cluster")
	if out["allowed"] != false {
		t.Fatalf("a cluster-scoped grant: %v", out)
	}
	must(r.call(token, http.MethodGet, sas, ""))(http.StatusForbidden, "list service accounts with its own token")
	must(r.call(token, http.MethodPost, sas+"/deployer/token", ""))(http.StatusForbidden, "a token of its own")
	must(r.call(token, http.MethodPost, authz+"/tokens", `{"name":"ci"}`))(http.StatusForbidden, "a PAT")

	// revoked by its jti
	tok = must(r.call(root, http.MethodPost, sas+"/deployer/token", ""))(http.StatusCreated, "token")
	revoked, _ := tok["token"].(string)
	if code := r.userinfo(revoked); code != http.StatusOK {
		t.Fatalf("before revocation: %d", code)
	}
	resp, _ := r.post("/oauth2/revoke", url.Values{"token": {revoked}, "client_id": {"system:serviceaccount:core:deployer"}})
	if resp.StatusCode != http.StatusOK || r.userinfo(revoked) != http.StatusUnauthorized {
		t.Fatalf("revoked: %d, still accepted", resp.StatusCode)
	}

	// deleted: its tokens refused, even once another is created under its name
	must(r.call(root, http.MethodDelete, sas+"/deployer", ""))(http.StatusNoContent, "delete")
	if code := r.userinfo(token); code != http.StatusUnauthorized {
		t.Fatalf("deleted: %d, want 401", code)
	}
	must(r.call(root, http.MethodPost, sas, `{"name":"deployer"}`))(http.StatusCreated, "recreate")
	if code := r.userinfo(token); code != http.StatusUnauthorized {
		t.Fatalf("recreated: the old token %d, want 401", code)
	}
	tok = must(r.call(root, http.MethodPost, sas+"/deployer/token", ""))(http.StatusCreated, "new token")
	fresh, _ := tok["token"].(string)
	if code := r.userinfo(fresh); code != http.StatusOK {
		t.Fatalf("the new one's token: %d", code)
	}
	// its namespace deleted: refused
	must(r.call(root, http.MethodDelete, "/apis/system.infrapi.io/v1/namespaces/core", ""))(http.StatusNoContent, "delete namespace")
	if code := r.userinfo(fresh); code != http.StatusUnauthorized {
		t.Fatalf("namespace deleted: %d, want 401", code)
	}
}

// No provider's user poses as one of Kayra's own identities: a user id
// under system: is refused, and the reserved groups are dropped from a
// human's.
func TestReservedSubjects(t *testing.T) {
	r := newOAuth2Rig(t)
	keys, err := gcrypto.LoadSigningKeys(r.cfg.Authentifications["self"].Local)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := gcrypto.MintSelfJWT(keys[0], "system:serviceaccount:core:deployer", []string{"system:serviceaccounts:core"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if code := r.userinfo(forged); code != http.StatusUnauthorized {
		t.Fatalf("a system: user id: %d, want 401", code)
	}
	human, err := gcrypto.MintSelfJWT(keys[0], "bootstrap", []string{"system:serviceaccounts:core"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	code, info := r.call(human, http.MethodGet, "/oauth2/userinfo", "")
	if code != http.StatusOK || info["kind"] != "user" {
		t.Fatalf("userinfo: %d %v", code, info)
	}
	for _, g := range info["groups"].([]any) {
		if strings.HasPrefix(g.(string), "system:") {
			t.Fatalf("a reserved group kept: %v", info["groups"])
		}
	}
}

// Personal access tokens, end to end: created by a user, scoped, used
// through /check and on Kayra's own routes, listed, revoked; another
// user's for a sysadmin only.
func TestPersonalAccessTokens(t *testing.T) {
	r := newOAuth2Rig(t)
	root := mintSysadminToken(t, r.cfg)
	const tokens = "/apis/authorization.infrapi.io/v1/tokens"
	code, out := r.call(root, http.MethodPost, tokens, `{"name":"ro","expires_in":"1h","scope":{"apis":["system.infrapi.io"],"verbs":["list","get"]}}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, out)
	}
	pat, id := out["token"].(string), out["id"].(string)

	// the scope, on Kayra's own routes and in /check
	if code, out := r.call(pat, http.MethodGet, "/apis/system.infrapi.io/v1/namespaces", ""); code != http.StatusOK {
		t.Fatalf("list namespaces: %d %v", code, out)
	}
	if code, _ := r.call(pat, http.MethodPost, "/apis/system.infrapi.io/v1/namespaces", `{"name":"x"}`); code != http.StatusForbidden {
		t.Fatalf("create a namespace, outside the scope: %d", code)
	}
	code, out = r.call(pat, http.MethodPost, "/apis/authorization.infrapi.io/v1/check", `{"api":"system.infrapi.io","resource":"namespaces","verb":"create"}`)
	if code != http.StatusOK || out["allowed"] != false || !strings.Contains(out["reason"].(string), "scope") {
		t.Fatalf("check outside the scope: %d %v", code, out)
	}
	code, out = r.call(pat, http.MethodPost, "/apis/authorization.infrapi.io/v1/check", `{"api":"system.infrapi.io","resource":"namespaces","verb":"list"}`)
	if code != http.StatusOK || out["allowed"] != true {
		t.Fatalf("check within the scope: %d %v", code, out)
	}

	// listed, its secret never; another user's: the sysadmin's only
	req, _ := http.NewRequest(http.MethodGet, r.kayra+tokens, nil)
	req.Header.Set("Authorization", "Bearer "+root)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), id) || strings.Contains(string(body), pat) {
		t.Fatalf("list: %s", body)
	}
	keys, err := gcrypto.LoadSigningKeys(r.cfg.Authentifications["self"].Local)
	if err != nil {
		t.Fatal(err)
	}
	nobody, _ := gcrypto.MintSelfJWT(keys[0], "nobody", []string{"sandbox-nobody"}, time.Hour)
	if code, _ := r.call(nobody, http.MethodGet, tokens+"?user=bootstrap", ""); code != http.StatusForbidden {
		t.Fatalf("nobody lists bootstrap's: %d", code)
	}
	if code, _ := r.call(nobody, http.MethodDelete, tokens+"/"+id+"?user=bootstrap", ""); code != http.StatusForbidden {
		t.Fatalf("nobody revokes bootstrap's: %d", code)
	}

	if code, _ := r.call(root, http.MethodDelete, tokens+"/"+id, ""); code != http.StatusNoContent {
		t.Fatalf("revoke: %d", code)
	}
	if code := r.userinfo(pat); code != http.StatusUnauthorized {
		t.Fatalf("revoked: %d", code)
	}
	if code, _ := r.call(root, http.MethodPost, "/api/v1/tokens", `{}`); code != http.StatusNotFound {
		t.Fatalf("the old route: %d", code)
	}
}
