package apiserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	gconfig "github.com/infrapi/kayra/internal/config"
)

// fakeOkta is Okta's org authorization server, as Kayra sees it: its
// access tokens name the org in aud, the app in cid.
type fakeOkta struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	kid      string
	clientID string // Kayra's client_id there: its ID tokens' aud
	aud      string // the aud its ID tokens carry: clientID when ""
	nonce    string // the nonce its ID tokens carry: the login's when ""
	sub      string // its ID tokens' sub: jdoe@example.com when ""
	mu       sync.Mutex
	pkce     map[string]string // code -> challenge
	nonces   map[string]string // code -> the login's nonce
}

func newFakeOkta(t *testing.T) *fakeOkta {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeOkta{key: key, kid: "okta-kid", clientID: "0oakayra", pkce: map[string]string{}, nonces: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOkta) serve(w http.ResponseWriter, r *http.Request) {
	base := f.srv.URL
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": base, "jwks_uri": base + "/keys",
			"authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token", "userinfo_endpoint": base + "/userinfo"})
	case "/keys":
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": f.kid, "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes()),
		}}})
	case "/authorize": // the human logs in at once
		q := r.URL.Query()
		code := "okta-" + q.Get("state")
		f.mu.Lock()
		f.pkce[code] = q.Get("code_challenge")
		f.nonces[code] = q.Get("nonce")
		f.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), http.StatusFound)
	case "/token":
		_ = r.ParseForm()
		f.mu.Lock()
		challenge, ok := f.pkce[r.PostForm.Get("code")]
		nonce := f.nonces[r.PostForm.Get("code")]
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge || r.PostForm.Get("client_id") != f.clientID {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		now := time.Now()
		aud := f.aud
		if aud == "" {
			aud = f.clientID
		}
		if f.nonce != "" {
			nonce = f.nonce
		}
		sub := f.sub
		if sub == "" {
			sub = "jdoe@example.com"
		}
		t := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": base, "aud": aud, "nonce": nonce, "sub": sub, "preferred_username": "jdoe@example.com",
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		})
		t.Header["kid"] = f.kid
		idToken, _ := t.SignedString(f.key)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "opaque-" + code(), "id_token": idToken, "token_type": "Bearer", "expires_in": 3600})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func code() string { return strings.Repeat("x", 8) }

// oauth2Rig is Kayra served over HTTP, its authorization server on, Okta
// its login provider.
type oauth2Rig struct {
	t      *testing.T
	kayra  string
	okta   *fakeOkta
	gitlab *fakeOkta    // a second provider, with oauth2: a choice
	client *http.Client // follows no redirect
}

func newOAuth2Rig(t *testing.T, withGitlab ...bool) *oauth2Rig {
	t.Helper()
	gin.SetMode(gin.TestMode)
	okta := newFakeOkta(t)
	okta.sub = "00u2u0ebcbkQyFOBz0i7" // Okta's: its ID token's sub is its user id
	var gitlab *fakeOkta
	cfg := testKayraConfig(t)
	users := cfg.Authorizations["dev"].Local.Path
	f, err := os.OpenFile(users, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("  - id: jdoe\n    groups: [sandbox-acme-devs]\n")
	_ = f.Close()
	cfg.Authentifications["okta"] = gconfig.AuthProvider{Authorization: "dev", Remote: &gconfig.RemoteAuthConfig{
		Enabled: true, URL: okta.srv.URL + "/.well-known/openid-configuration",
		Claims: map[string]gconfig.ClaimValues{"cid": {"0oakayra"}},
		UserID: gconfig.UserIDConfig{From: "token", Field: "sub", Filter: "^([^@]+)@"},
		// the login is the ID token's preferred_username
		OAuth2: &gconfig.OAuth2LoginConfig{ClientID: "0oakayra", UserID: &gconfig.UserIDConfig{From: "token", Field: "preferred_username", Filter: "^([^@]+)@"}},
	}}
	// a provider whose tokens a CI job presents: never a login
	cfg.Authentifications["ci"] = gconfig.AuthProvider{Authorization: "dev", Remote: &gconfig.RemoteAuthConfig{
		Enabled: true, URL: okta.srv.URL + "/.well-known/openid-configuration",
		Claims: map[string]gconfig.ClaimValues{"aud": {"api://infrapi"}}, UserID: gconfig.UserIDConfig{From: "token", Field: "sub"},
	}}
	if len(withGitlab) > 0 {
		gitlab = newFakeOkta(t)
		gitlab.kid, gitlab.clientID = "gitlab-kid", "gl-kayra"
		cfg.Authentifications["gitlab"] = gconfig.AuthProvider{Authorization: "dev", Remote: &gconfig.RemoteAuthConfig{
			Enabled: true, URL: gitlab.srv.URL + "/.well-known/openid-configuration",
			Claims: map[string]gconfig.ClaimValues{"aud": {"api://infrapi"}},
			UserID: gconfig.UserIDConfig{From: "token", Field: "user_login"},
			OAuth2: &gconfig.OAuth2LoginConfig{ClientID: "gl-kayra", UserID: &gconfig.UserIDConfig{From: "token", Field: "sub", Filter: "^([^@]+)@"}},
		}}
	}
	// infrapi-cli is built in
	cfg.OAuth2 = gconfig.OAuth2ServerConfig{Enabled: true, Clients: []gconfig.OAuth2Client{
		{ID: "tool", Name: "A tool", RedirectURIs: []string{"https://tool.example.com/cb"}},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	srv := httptest.NewUnstartedServer(nil)
	app := testAppConfig()
	app.AppUrl = "http://" + srv.Listener.Addr().String()
	engine, err := Build(app, cfg)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	srv.Config.Handler = engine
	srv.Start()
	t.Cleanup(srv.Close)
	return &oauth2Rig{t: t, kayra: srv.URL, okta: okta, gitlab: gitlab,
		client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (r *oauth2Rig) get(u string) *http.Response {
	r.t.Helper()
	resp, err := r.client.Get(u)
	if err != nil {
		r.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

func (r *oauth2Rig) post(path string, form url.Values, cookies ...*http.Cookie) (*http.Response, map[string]any) {
	r.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, r.kayra+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func pkce() (verifier, challenge string) {
	verifier = "verifier-" + strings.Repeat("v", 40)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorize runs /oauth2/authorize and the login at Okta: the response
// Kayra's callback gave, the client's redirect for a first-party client.
func (r *oauth2Rig) authorize(params url.Values) *http.Response {
	r.t.Helper()
	resp := r.get(r.kayra + "/oauth2/authorize?" + params.Encode())
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), r.okta.srv.URL) {
		return resp
	}
	atOkta := r.get(resp.Header.Get("Location"))
	cb, err := r.client.Get(atOkta.Header.Get("Location"))
	if err != nil {
		r.t.Fatal(err)
	}
	return cb
}

func cliParams(challenge string, kayra string) url.Values {
	return url.Values{"response_type": {"code"}, "client_id": {"infrapi-cli"}, "redirect_uri": {"http://127.0.0.1:43210/callback"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"xyz"}, "resource": {kayra}}
}

func (r *oauth2Rig) userinfo(token string) int {
	r.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, r.kayra+"/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// The whole flow, a first-party client: authorize, Okta's login, the code,
// the tokens; the access token Kayra's own; refresh rotated, a refresh
// token used twice revoking the login; revocation.
func TestOAuth2Server(t *testing.T) {
	r := newOAuth2Rig(t)

	meta := r.get(r.kayra + "/.well-known/oauth-authorization-server")
	if meta.StatusCode != http.StatusOK {
		t.Fatalf("metadata: %d", meta.StatusCode)
	}

	verifier, challenge := pkce()
	cb := r.authorize(cliParams(challenge, r.kayra))
	loc, _ := url.Parse(cb.Header.Get("Location"))
	q := loc.Query()
	if cb.StatusCode != http.StatusFound || loc.Host != "127.0.0.1:43210" || q.Get("state") != "xyz" || q.Get("iss") != r.kayra || q.Get("code") == "" {
		t.Fatalf("callback: %d %s", cb.StatusCode, cb.Header.Get("Location"))
	}
	code := q.Get("code")
	tokenForm := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"infrapi-cli"},
		"redirect_uri": {"http://127.0.0.1:43210/callback"}, "code_verifier": {verifier}}
	resp, tok := r.post("/oauth2/token", tokenForm)
	if resp.StatusCode != http.StatusOK || tok["token_type"] != "Bearer" || tok["refresh_token"] == nil || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("token: %d %v", resp.StatusCode, tok)
	}
	access, refresh := tok["access_token"].(string), tok["refresh_token"].(string)
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(access, claims); err != nil || claims["sub"] != "jdoe" || claims["aud"] != r.kayra ||
		claims["client_id"] != "infrapi-cli" || claims["iss"] != r.kayra {
		t.Fatalf("access token: %v %v", claims, err)
	}
	if got := r.userinfo(access); got != http.StatusOK {
		t.Fatalf("userinfo with Kayra's access token: %d", got)
	}
	// userinfo tells an app what the token was issued for, and to whom
	req, _ := http.NewRequest(http.MethodGet, r.kayra+"/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	uresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var info map[string]any
	_ = json.NewDecoder(uresp.Body).Decode(&info)
	_ = uresp.Body.Close()
	if aud, _ := info["aud"].([]any); len(aud) != 1 || aud[0] != r.kayra || info["client_id"] != "infrapi-cli" {
		t.Fatalf("userinfo: %v", info)
	}
	// the code is single use
	if resp, out := r.post("/oauth2/token", tokenForm); resp.StatusCode != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("a code twice: %d %v", resp.StatusCode, out)
	}

	// refresh: rotated
	refreshForm := func(rt string) url.Values {
		return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {"infrapi-cli"}}
	}
	resp, tok2 := r.post("/oauth2/token", refreshForm(refresh))
	if resp.StatusCode != http.StatusOK || tok2["refresh_token"] == refresh {
		t.Fatalf("refresh: %d %v", resp.StatusCode, tok2)
	}
	refresh2 := tok2["refresh_token"].(string)
	// the old one again: the whole login revoked, the new one with it
	if resp, out := r.post("/oauth2/token", refreshForm(refresh)); resp.StatusCode != http.StatusBadRequest || !strings.Contains(out["error_description"].(string), "used already") {
		t.Fatalf("a refresh token twice: %d %v", resp.StatusCode, out)
	}
	if resp, _ := r.post("/oauth2/token", refreshForm(refresh2)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("the login revoked, its new refresh token: %d", resp.StatusCode)
	}

	// a new login; revoke its access token, then its refresh token
	cb = r.authorize(cliParams(challenge, r.kayra))
	loc, _ = url.Parse(cb.Header.Get("Location"))
	tokenForm.Set("code", loc.Query().Get("code"))
	_, tok3 := r.post("/oauth2/token", tokenForm)
	access3, refresh3 := tok3["access_token"].(string), tok3["refresh_token"].(string)
	if resp, _ := r.post("/oauth2/revoke", url.Values{"token": {access3}, "client_id": {"infrapi-cli"}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if got := r.userinfo(access3); got != http.StatusUnauthorized {
		t.Fatalf("a revoked access token: %d", got)
	}
	r.post("/oauth2/revoke", url.Values{"token": {refresh3}, "client_id": {"infrapi-cli"}})
	if resp, _ := r.post("/oauth2/token", refreshForm(refresh3)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a revoked refresh token: %d", resp.StatusCode)
	}
}

// A third-party client is shown the consent page; the consent is the
// browser's that was shown it.
func TestOAuth2ServerConsent(t *testing.T) {
	r := newOAuth2Rig(t)
	_, challenge := pkce()
	params := cliParams(challenge, r.kayra)
	params.Set("client_id", "tool")
	params.Set("redirect_uri", "https://tool.example.com/cb")
	page := r.authorize(params)
	defer func() { _ = page.Body.Close() }()
	body := new(strings.Builder)
	_, _ = io.Copy(body, page.Body)
	if page.StatusCode != http.StatusOK || !strings.Contains(body.String(), "A tool wants to act on your behalf") || !strings.Contains(body.String(), "tool.example.com") {
		t.Fatalf("consent page: %d %s", page.StatusCode, body)
	}
	var cookie *http.Cookie
	for _, c := range page.Cookies() {
		if c.Name == "kayra_consent" {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly {
		t.Fatalf("no consent cookie: %v", page.Cookies())
	}
	form := url.Values{"consent": {cookie.Value}, "decision": {"allow"}}
	if resp, _ := r.post("/oauth2/consent", form); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("without the cookie: %d", resp.StatusCode)
	}
	resp, _ := r.post("/oauth2/consent", form, cookie)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc.Host != "tool.example.com" || loc.Query().Get("code") == "" {
		t.Fatalf("allowed: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// used: again, refused
	if resp, _ := r.post("/oauth2/consent", form, cookie); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a consent twice: %d", resp.StatusCode)
	}
}

// What is refused, and how: an error page until the client and its
// redirect URI are known, a redirect with the error after.
func TestOAuth2ServerRefusals(t *testing.T) {
	r := newOAuth2Rig(t)
	verifier, challenge := pkce()
	for name, c := range map[string]struct {
		set    map[string]string
		status int
		err    string
	}{
		"unknown client":   {map[string]string{"client_id": "nope"}, http.StatusBadRequest, ""},
		"unknown redirect": {map[string]string{"redirect_uri": "http://127.0.0.1:1/elsewhere"}, http.StatusBadRequest, ""},
		"another host":     {map[string]string{"redirect_uri": "https://evil.example.com/callback"}, http.StatusBadRequest, ""},
		"no PKCE":          {map[string]string{"code_challenge": ""}, http.StatusFound, "invalid_request"},
		"plain PKCE":       {map[string]string{"code_challenge_method": "plain"}, http.StatusFound, "invalid_request"},
		"not code":         {map[string]string{"response_type": "token"}, http.StatusFound, "unsupported_response_type"},
		"another resource": {map[string]string{"resource": "https://elsewhere.example.com"}, http.StatusFound, "invalid_target"},
	} {
		p := cliParams(challenge, r.kayra)
		for k, v := range c.set {
			p.Set(k, v)
		}
		resp := r.get(r.kayra + "/oauth2/authorize?" + p.Encode())
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != c.status || c.err != "" && (loc.Query().Get("error") != c.err || loc.Host != "127.0.0.1:43210") {
			t.Errorf("%s: %d %s", name, resp.StatusCode, resp.Header.Get("Location"))
		}
	}

	// an ID token for another app, or another login's: refused at the callback
	for name, set := range map[string]func(){"another aud": func() { r.okta.aud = "0oaanother" }, "another nonce": func() { r.okta.nonce = "replayed" }} {
		set()
		cb := r.authorize(cliParams(challenge, r.kayra))
		loc, _ := url.Parse(cb.Header.Get("Location"))
		if loc.Query().Get("error") != "access_denied" || !strings.Contains(loc.Query().Get("error_description"), "ID token") {
			t.Fatalf("%s: %s", name, cb.Header.Get("Location"))
		}
		r.okta.aud, r.okta.nonce = "", ""
	}

	// a wrong verifier
	cb := r.authorize(cliParams(challenge, r.kayra))
	loc, _ := url.Parse(cb.Header.Get("Location"))
	resp, out := r.post("/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "client_id": {"infrapi-cli"},
		"redirect_uri": {"http://127.0.0.1:43210/callback"}, "code_verifier": {verifier + "x"}})
	if resp.StatusCode != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("a wrong verifier: %d %v", resp.StatusCode, out)
	}
	// no dynamic registration unless enabled
	if resp, _ := r.post("/oauth2/register", url.Values{}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("register: %d", resp.StatusCode)
	}
}

// infrapi-cli auth login --no-browser: Kayra shows the code to paste, which
// redeems with its verifier; no other client may ask for it.
func TestOAuth2ServerOOB(t *testing.T) {
	r := newOAuth2Rig(t)
	verifier, challenge := pkce()
	p := cliParams(challenge, r.kayra)
	p.Set("redirect_uri", "urn:ietf:wg:oauth:2.0:oob")
	page := r.authorize(p)
	body, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	i := strings.Index(string(body), "user-select:all\">")
	if page.StatusCode != http.StatusOK || i < 0 {
		t.Fatalf("code page: %d %s", page.StatusCode, body)
	}
	code := string(body)[i+len("user-select:all\">"):]
	code = code[:strings.Index(code, "<")]
	resp, out := r.post("/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"infrapi-cli"},
		"redirect_uri": {"urn:ietf:wg:oauth:2.0:oob"}, "code_verifier": {verifier}})
	if resp.StatusCode != http.StatusOK || out["access_token"] == nil {
		t.Fatalf("token: %d %v", resp.StatusCode, out)
	}
	p.Set("client_id", "tool")
	if resp := r.get(r.kayra + "/oauth2/authorize?" + p.Encode()); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("another client, oob: %d", resp.StatusCode)
	}
}

// Several providers with oauth2: the human chooses, on a page; one without
// oauth2, whose tokens a CI job presents, is never offered.
func TestOAuth2ServerChoice(t *testing.T) {
	r := newOAuth2Rig(t, true)
	verifier, challenge := pkce()
	page := r.get(r.kayra + "/oauth2/authorize?" + cliParams(challenge, r.kayra).Encode())
	resp, err := r.client.Get(r.kayra + "/oauth2/authorize?" + cliParams(challenge, r.kayra).Encode())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if page.StatusCode != http.StatusOK || !strings.Contains(string(body), ">gitlab<") || !strings.Contains(string(body), ">okta<") || strings.Contains(string(body), ">ci<") {
		t.Fatalf("choice page: %d %s", page.StatusCode, body)
	}
	i := strings.Index(string(body), `/oauth2/login?`)
	href := string(body)[i:]
	href = strings.ReplaceAll(href[:strings.Index(href, `"`)], "&amp;", "&")
	u, _ := url.Parse(r.kayra + href)
	q := u.Query()
	q.Set("provider", "gitlab")
	u.RawQuery = q.Encode()
	atGitlab := r.get(u.String())
	if !strings.HasPrefix(atGitlab.Header.Get("Location"), r.gitlab.srv.URL) {
		t.Fatalf("to gitlab: %d %s", atGitlab.StatusCode, atGitlab.Header.Get("Location"))
	}
	back := r.get(r.get(atGitlab.Header.Get("Location")).Header.Get("Location"))
	loc, _ := url.Parse(back.Header.Get("Location"))
	resp2, tok := r.post("/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "client_id": {"infrapi-cli"},
		"redirect_uri": {"http://127.0.0.1:43210/callback"}, "code_verifier": {verifier}})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("token: %d %v %s", resp2.StatusCode, tok, back.Header.Get("Location"))
	}
	claims := jwt.MapClaims{}
	_, _, _ = jwt.NewParser().ParseUnverified(tok["access_token"].(string), claims)
	if claims["sub"] != "jdoe" {
		t.Fatalf("logged in at gitlab: %v", claims)
	}
	// the choice is single use; a provider without oauth2 is refused
	if again := r.get(u.String()); again.StatusCode != http.StatusBadRequest {
		t.Fatalf("a choice twice: %d", again.StatusCode)
	}
	resp, _ = r.client.Get(r.kayra + "/oauth2/authorize?" + cliParams(challenge, r.kayra).Encode())
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	i = strings.Index(string(body), `/oauth2/login?`)
	href = string(body)[i:]
	href = strings.ReplaceAll(href[:strings.Index(href, `"`)], "&amp;", "&")
	u, _ = url.Parse(r.kayra + href)
	q = u.Query()
	q.Set("provider", "ci")
	u.RawQuery = q.Encode()
	ci := r.get(u.String())
	if l, _ := url.Parse(ci.Header.Get("Location")); l.Query().Get("error") != "invalid_request" {
		t.Fatalf("a provider without oauth2: %s", ci.Header.Get("Location"))
	}
}
