package oauth2server

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/infrapi/kayra/internal/authn"
	"github.com/infrapi/kayra/internal/oidc"
)

const consentCookie = "kayra_consent"

// authorize checks an authorization request, then sends the human to the
// login provider. Until the client and its redirect URI are known good, an
// error is shown, never redirected (OAuth 2.1 section 4.1.2.1).
func (s *Server) authorize(c *gin.Context) {
	q := c.Request.URL.Query()
	cl, err := s.client(q.Get("client_id"))
	if err != nil {
		s.errorPage(c, http.StatusBadRequest, "Unknown client", err.Error())
		return
	}
	redirect := q.Get("redirect_uri")
	if !cl.matchRedirect(redirect) {
		s.errorPage(c, http.StatusBadRequest, "Unknown redirect URI",
			fmt.Sprintf("%q is not one of client %s's redirect URIs", redirect, cl.Name))
		return
	}
	req := request{
		Client: cl.ID, ClientName: cl.Name, FirstParty: cl.FirstParty, RedirectURI: redirect,
		State: q.Get("state"), Challenge: q.Get("code_challenge"), Resource: q.Get("resource"), Scope: q.Get("scope"),
	}
	switch {
	case q.Get("response_type") != "code":
		s.redirectError(c, req, "unsupported_response_type", "response_type is code")
		return
	case req.Challenge == "" || q.Get("code_challenge_method") != "S256":
		s.redirectError(c, req, "invalid_request", "PKCE is required: code_challenge, code_challenge_method S256")
		return
	case req.Resource == "":
		req.Resource = s.issuer // a token for Kayra itself
	}
	if !s.allowedResource(req.Resource) {
		s.redirectError(c, req, "invalid_target", fmt.Sprintf("resource %q is no InfraPI app's (oauth2.resources)", req.Resource))
		return
	}

	providers := s.cfgAll.LoginProviders()
	if len(providers) == 1 {
		s.startLogin(c, req, providers[0])
		return
	}
	// several: the human chooses
	choice := random(24)
	if err := s.put("choices", hash(choice), req, loginTTL); err != nil {
		s.redirectError(c, req, "server_error", err.Error())
		return
	}
	var links strings.Builder
	for _, p := range providers {
		href := "/oauth2/login?" + url.Values{"choice": {choice}, "provider": {p}}.Encode()
		fmt.Fprintf(&links, `<a class="choice" href="%s">%s</a>`, html.EscapeString(href), html.EscapeString(p))
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Header("X-Frame-Options", "DENY")
	c.String(http.StatusOK, choicePage, html.EscapeString(req.ClientName), links.String())
}

// chosen is the provider the human chose on the page: the login goes on
// there.
func (s *Server) chosen(c *gin.Context) {
	var req request
	ok, err := s.take("choices", hash(c.Query("choice")), &req)
	if err != nil || !ok {
		s.errorPage(c, http.StatusBadRequest, "Login expired", "this login is unknown, or took too long: start it again from your application")
		return
	}
	provider := c.Query("provider")
	if !slices.Contains(s.cfgAll.LoginProviders(), provider) {
		s.redirectError(c, req, "invalid_request", fmt.Sprintf("%q is no provider to log in with", provider))
		return
	}
	s.startLogin(c, req, provider)
}

// startLogin sends the human to provider's authorization endpoint, with a
// PKCE and a nonce of Kayra's own, openid among the scopes.
func (s *Server) startLogin(c *gin.Context, req request, provider string) {
	p := s.cfgAll.Authentifications[provider]
	doc, err := oidc.FetchDiscovery(p.Remote.URL, p.Remote.Proxy)
	if err != nil || doc.AuthorizationEndpoint == "" {
		s.redirectError(c, req, "temporarily_unavailable", fmt.Sprintf("provider %s: %v", provider, err))
		return
	}
	verifier, state, nonce := random(32), random(24), random(24)
	if err := s.put("logins", hash(state), pendingLogin{request: req, Provider: provider, Verifier: verifier, Nonce: nonce}, loginTTL); err != nil {
		s.redirectError(c, req, "server_error", err.Error())
		return
	}
	scopes := p.Remote.OAuth2.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	if !slices.Contains(scopes, "openid") {
		scopes = append([]string{"openid"}, scopes...)
	}
	to := doc.AuthorizationEndpoint + "?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {p.Remote.OAuth2.ClientID},
		"redirect_uri":          {s.issuer + "/oauth2/callback"},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challengeOf(verifier)},
		"code_challenge_method": {"S256"},
	}.Encode()
	c.Redirect(http.StatusFound, to)
}

// callback is the provider's redirect: Kayra redeems its code, checks the
// provider's ID token (OIDC: Kayra is the client), then resolves the user
// as any token of that provider resolves.
func (s *Server) callback(c *gin.Context) {
	q := c.Request.URL.Query()
	var p pendingLogin
	ok, err := s.take("logins", hash(q.Get("state")), &p)
	if err != nil || !ok {
		s.errorPage(c, http.StatusBadRequest, "Login expired", "this login is unknown, or took too long: start it again from your application")
		return
	}
	if e := q.Get("error"); e != "" {
		s.redirectError(c, p.request, "access_denied", "provider "+p.Provider+": "+e+" "+q.Get("error_description"))
		return
	}
	v, err := s.redeem(p, q.Get("code"))
	if err != nil {
		s.redirectError(c, p.request, "access_denied", err.Error())
		return
	}
	ac, err := s.auth.ResolveVerified(v, s.cfgAll.Authentifications[p.Provider].Remote.OAuth2.UserID)
	if err != nil {
		s.redirectError(c, p.request, "access_denied", "the user: "+err.Error())
		return
	}
	who := identity{UserID: ac.UserID, Provider: ac.Provider, Authorization: ac.Authorization, Groups: ac.Groups}
	if p.FirstParty {
		s.issueCode(c, p.request, who)
		return
	}
	id := random(24)
	if err := s.put("consents", hash(id), pendingConsent{request: p.request, identity: who}, consentTTL); err != nil {
		s.redirectError(c, p.request, "server_error", err.Error())
		return
	}
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(consentCookie, id, int(consentTTL.Seconds()), "/oauth2/consent", "", strings.HasPrefix(s.issuer, "https://"), true)
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Header("X-Frame-Options", "DENY")
	c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	e := html.EscapeString
	c.String(http.StatusOK, consentPage, e(p.ClientName), e(redirectHost(p.RedirectURI)), e(p.Resource), e(who.UserID), e(id))
}

// redeem exchanges the provider's code, with Kayra's PKCE verifier, and
// checks the ID token it answers: signed by the provider's key, its iss the
// provider's issuer, its aud Kayra's client_id there, its nonce the
// login's, not expired. Its access token comes along, for a user_id read
// at the provider's userinfo.
func (s *Server) redeem(p pendingLogin, code string) (*authn.Verified, error) {
	prov := s.cfgAll.Authentifications[p.Provider]
	doc, err := oidc.FetchDiscovery(prov.Remote.URL, prov.Remote.Proxy)
	if err != nil {
		return nil, fmt.Errorf("provider %s: %w", p.Provider, err)
	}
	if doc.TokenEndpoint == "" {
		return nil, fmt.Errorf("provider %s has no token_endpoint", p.Provider)
	}
	hc, err := oidc.ClientFor(prov.Remote.Proxy)
	if err != nil {
		return nil, err
	}
	resp, err := hc.PostForm(doc.TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {s.issuer + "/oauth2/callback"},
		"client_id":     {prov.Remote.OAuth2.ClientID},
		"code_verifier": {p.Verifier},
	})
	if err != nil {
		return nil, fmt.Errorf("provider %s's token endpoint: %w", p.Provider, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("provider %s's token endpoint answered %d: %w", p.Provider, resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || out.IDToken == "" {
		return nil, fmt.Errorf("provider %s's token endpoint answered %d, no ID token: %s %s", p.Provider, resp.StatusCode, out.Error, out.Description)
	}
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(out.IDToken, claims, func(t *jwt.Token) (any, error) {
		// the provider's own keys, refreshed once when the kid is new: two
		// providers may share an issuer and its keys
		kid, _ := t.Header["kid"].(string)
		keys, err := s.auth.Manager.KeysFor(p.Provider)
		if err == nil && !slices.ContainsFunc(keys, func(k oidc.JWK) bool { return k.Kid == kid }) {
			keys, err = s.auth.Manager.RefreshRemote(p.Provider)
		}
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			if k.Kid == kid {
				return k.PublicKey()
			}
		}
		return nil, fmt.Errorf("provider %s has no key %q", p.Provider, kid)
	}, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}), jwt.WithExpirationRequired(), jwt.WithIssuedAt(),
		jwt.WithIssuer(doc.Issuer), jwt.WithAudience(prov.Remote.OAuth2.ClientID))
	if err != nil {
		return nil, fmt.Errorf("provider %s's ID token: %w", p.Provider, err)
	}
	if nonce, _ := claims["nonce"].(string); nonce != p.Nonce {
		return nil, fmt.Errorf("provider %s's ID token: its nonce is not this login's", p.Provider)
	}
	return &authn.Verified{Provider: p.Provider, Claims: claims, Token: out.AccessToken}, nil
}

// consent is the human's answer on the consent page: the form's id must be
// the cookie's, the browser's that was shown the page.
func (s *Server) consent(c *gin.Context) {
	id := c.PostForm("consent")
	cookie, _ := c.Cookie(consentCookie)
	if id == "" || cookie != id {
		s.errorPage(c, http.StatusBadRequest, "Consent expired", "this consent is unknown, or was not given in this browser")
		return
	}
	c.SetCookie(consentCookie, "", -1, "/oauth2/consent", "", strings.HasPrefix(s.issuer, "https://"), true)
	var p pendingConsent
	ok, err := s.take("consents", hash(id), &p)
	if err != nil || !ok {
		s.errorPage(c, http.StatusBadRequest, "Consent expired", "this consent is unknown, or took too long: start it again from your application")
		return
	}
	if c.PostForm("decision") != "allow" {
		s.redirectError(c, p.request, "access_denied", "the user denied it")
		return
	}
	s.issueCode(c, p.request, p.identity)
}

// issueCode sends the client back with an authorization code, single use,
// bound to its request and to who logged in.
func (s *Server) issueCode(c *gin.Context, req request, who identity) {
	code := random(32)
	if err := s.put("codes", hash(code), authCode{request: req, identity: who}, codeTTL); err != nil {
		s.redirectError(c, req, "server_error", err.Error())
		return
	}
	if req.RedirectURI == OOBRedirectURI {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Cache-Control", "no-store")
		c.String(http.StatusOK, codePage, html.EscapeString(code))
		return
	}
	v := url.Values{"code": {code}, "iss": {s.issuer}}
	if req.State != "" {
		v.Set("state", req.State)
	}
	c.Redirect(http.StatusFound, withQuery(req.RedirectURI, v))
}

// redirectError sends the client back with an error (RFC 6749 section
// 4.1.2.1), its state and the issuer (RFC 9207).
func (s *Server) redirectError(c *gin.Context, req request, code, desc string) {
	if req.RedirectURI == OOBRedirectURI {
		s.errorPage(c, http.StatusBadRequest, "Login failed", code+": "+desc)
		return
	}
	v := url.Values{"error": {code}, "error_description": {desc}, "iss": {s.issuer}}
	if req.State != "" {
		v.Set("state", req.State)
	}
	c.Redirect(http.StatusFound, withQuery(req.RedirectURI, v))
}

func withQuery(uri string, v url.Values) string {
	sep := "?"
	if strings.Contains(uri, "?") {
		sep = "&"
	}
	return uri + sep + v.Encode()
}

func (s *Server) errorPage(c *gin.Context, status int, title, detail string) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.String(status, errorPage, html.EscapeString(title), html.EscapeString(title), html.EscapeString(detail))
}

// pageHead is every page's head: the InfraPI portal's look, dark surfaces,
// hairline edges, its blue accent, Geist when installed; nothing fetched,
// the pages' Content-Security-Policy allowing no font or image. Its percent
// signs are doubled: every page is a format.
const pageHead = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark">
<style>
:root{--bg:#050506;--card:#121215;--hover:#18181c;--edge:#222227;--text:#ededef;--text-2:#a1a1ab;--muted:#6e6e78;
--accent:#1a8cff;--accent-2:#00d8ff;--accent-dim:#0075fd;--warning:#f59e0b;--danger:#ef4444;--code-bg:#12151c;--code-edge:#262a33;
--font:"Geist",ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;--mono:"Geist Mono",ui-monospace,"SFMono-Regular",Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem;font-family:var(--font);
background:radial-gradient(60rem 30rem at 50%% -10%%,color-mix(in srgb,var(--accent) 14%%,transparent),transparent),var(--bg);color:var(--text)}
.card{width:100%%;max-width:28rem;background:var(--card);border:1px solid var(--edge);border-radius:14px;padding:2rem 2.2rem;
box-shadow:0 20px 60px rgba(0,0,0,.45)}
.brand{font-weight:700;letter-spacing:-.01em;font-size:.95rem;margin-bottom:1.4rem;color:var(--text-2)}
.brand b{background:linear-gradient(90deg,var(--accent),var(--accent-2));-webkit-background-clip:text;background-clip:text;color:transparent}
h1{font-size:1.2rem;font-weight:600;margin:0 0 1rem;line-height:1.4}
p{color:var(--text-2);font-size:.9rem;line-height:1.55;margin:.9rem 0}
p.warn{color:var(--warning)}
dl{display:grid;grid-template-columns:auto 1fr;gap:.45rem 1rem;margin:1.2rem 0;font-size:.9rem}
dt{color:var(--muted)}dd{margin:0;word-break:break-all}
strong{color:var(--text)}
.actions{display:flex;gap:.6rem;margin-top:1.5rem}
button,a.choice{font:inherit;font-weight:600;font-size:.95rem;border-radius:9px;padding:.65rem 1.3rem;cursor:pointer;text-decoration:none;
border:1px solid var(--edge);background:transparent;color:var(--text)}
button:hover,a.choice:hover{background:var(--hover)}
button.primary,a.choice{background:var(--accent);border-color:var(--accent);color:#fff}
button.primary:hover,a.choice:hover{background:var(--accent-dim)}
a.choice{display:block;text-align:center;margin:.6rem 0}
code.code{display:block;font-family:var(--mono);font-size:.95rem;background:var(--code-bg);border:1px solid var(--code-edge);
border-radius:9px;padding:.8rem 1rem;word-break:break-all;margin:1rem 0}
</style>`

const consentPage = pageHead + `<title>Authorize %[1]s</title></head><body><main class="card">
<div class="brand"><b>InfraPI</b> · Kayra</div>
<h1>%[1]s wants to act on your behalf</h1>
<dl><dt>It sends you back to</dt><dd><strong>%[2]s</strong></dd><dt>On</dt><dd>%[3]s</dd><dt>As</dt><dd>%[4]s</dd></dl>
<p>It gets what your roles grant you there, until you revoke it. Allow it only if you started this from %[2]s.</p>
<form method="post" action="/oauth2/consent"><input type="hidden" name="consent" value="%[5]s">
<div class="actions"><button class="primary" name="decision" value="allow">Allow</button><button name="decision" value="deny">Deny</button></div>
</form></main></body></html>`

const codePage = pageHead + `<title>Login code</title></head><body><main class="card">
<div class="brand"><b>InfraPI</b> · Kayra</div>
<h1>Paste this code into your terminal</h1>
<code class="code" id="code" style="user-select:all">%s</code>
<div class="actions"><button class="primary" type="button" onclick="navigator.clipboard&&navigator.clipboard.writeText(document.getElementById('code').textContent);this.textContent='Copied'">Copy</button></div>
<p>Paste it at the <code>infrapi-cli auth login --no-browser</code> prompt. It works once, within a minute.</p>
<p class="warn">Only paste it into a terminal where you started this login yourself. Never send it to anyone.</p>
</main></body></html>`

const choicePage = pageHead + `<title>Log in</title></head><body><main class="card">
<div class="brand"><b>InfraPI</b> · Kayra</div>
<h1>Log in to %s with</h1>%s
<p>You will be redirected there to sign in.</p></main></body></html>`

const errorPage = pageHead + `<title>%s</title></head><body><main class="card">
<div class="brand"><b>InfraPI</b> · Kayra</div>
<h1>%s</h1><p>%s</p></main></body></html>`
