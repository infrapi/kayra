package oauth2server

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

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

	// the login provider, with a PKCE of Kayra's own
	doc, err := oidc.FetchDiscovery(s.login.Remote.URL, s.login.Remote.Proxy)
	if err != nil || doc.AuthorizationEndpoint == "" {
		s.redirectError(c, req, "temporarily_unavailable", fmt.Sprintf("the login provider: %v", err))
		return
	}
	verifier, state := random(32), random(24)
	if err := s.put("logins", hash(state), pendingLogin{request: req, Verifier: verifier}, loginTTL); err != nil {
		s.redirectError(c, req, "server_error", err.Error())
		return
	}
	scopes := s.login.Remote.OAuth2.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	to := doc.AuthorizationEndpoint + "?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {s.login.Remote.OAuth2.ClientID},
		"redirect_uri":          {s.issuer + "/oauth2/callback"},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"code_challenge":        {challengeOf(verifier)},
		"code_challenge_method": {"S256"},
	}.Encode()
	c.Redirect(http.StatusFound, to)
}

// callback is the login provider's redirect: Kayra redeems its code, and
// checks its token as any of the provider's tokens is checked.
func (s *Server) callback(c *gin.Context) {
	q := c.Request.URL.Query()
	var p pendingLogin
	ok, err := s.take("logins", hash(q.Get("state")), &p)
	if err != nil || !ok {
		s.errorPage(c, http.StatusBadRequest, "Login expired", "this login is unknown, or took too long: start it again from your application")
		return
	}
	if e := q.Get("error"); e != "" {
		s.redirectError(c, p.request, "access_denied", "the login provider: "+e+" "+q.Get("error_description"))
		return
	}
	token, err := s.redeem(q.Get("code"), p.Verifier)
	if err != nil {
		s.redirectError(c, p.request, "server_error", err.Error())
		return
	}
	ac, err := s.auth.Resolve(token)
	if err != nil {
		s.redirectError(c, p.request, "access_denied", "the login provider's token: "+err.Error())
		return
	}
	if ac.Provider != s.cfg.Login {
		s.redirectError(c, p.request, "access_denied", fmt.Sprintf("a token of provider %s, not %s", ac.Provider, s.cfg.Login))
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

// redeem exchanges the login provider's code for its access token.
func (s *Server) redeem(code, verifier string) (string, error) {
	doc, err := oidc.FetchDiscovery(s.login.Remote.URL, s.login.Remote.Proxy)
	if err != nil {
		return "", fmt.Errorf("the login provider: %w", err)
	}
	if doc.TokenEndpoint == "" {
		return "", fmt.Errorf("the login provider has no token_endpoint")
	}
	hc, err := oidc.ClientFor(s.login.Remote.Proxy)
	if err != nil {
		return "", err
	}
	resp, err := hc.PostForm(doc.TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {s.issuer + "/oauth2/callback"},
		"client_id":     {s.login.Remote.OAuth2.ClientID},
		"code_verifier": {verifier},
	})
	if err != nil {
		return "", fmt.Errorf("the login provider's token endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("the login provider's token endpoint answered %d: %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		return "", fmt.Errorf("the login provider's token endpoint answered %d: %s %s", resp.StatusCode, out.Error, out.Description)
	}
	return out.AccessToken, nil
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

const pageStyle = `<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.3rem}dl{display:grid;grid-template-columns:auto 1fr;gap:.4rem 1rem}dt{color:#666}dd{margin:0;word-break:break-all}
button{font-size:1rem;padding:.5rem 1.2rem;margin-right:.5rem;border-radius:.4rem;border:1px solid #888;background:#fff;cursor:pointer}
button[value=allow]{background:#1a56db;color:#fff;border-color:#1a56db}</style>`

const consentPage = `<!doctype html><html><head><meta charset="utf-8"><title>Authorize %[1]s</title>` + pageStyle + `</head><body>
<h1>%[1]s wants to act on your behalf</h1>
<dl><dt>It sends you back to</dt><dd><strong>%[2]s</strong></dd><dt>On</dt><dd>%[3]s</dd><dt>As</dt><dd>%[4]s</dd></dl>
<p>It gets what your roles grant you there, until you revoke it. Allow it only if you started this from %[2]s.</p>
<form method="post" action="/oauth2/consent"><input type="hidden" name="consent" value="%[5]s">
<button name="decision" value="allow">Allow</button><button name="decision" value="deny">Deny</button></form></body></html>`

const codePage = `<!doctype html><html><head><meta charset="utf-8"><title>Login code</title>` + pageStyle + `</head><body>
<h1>Logged in</h1><p>Paste this code in your terminal, where infrapi-cli asks for it:</p>
<p><code style="font-size:1.1rem;word-break:break-all;user-select:all">%s</code></p><p>It works once, within a minute.</p></body></html>`

const errorPage = `<!doctype html><html><head><meta charset="utf-8"><title>%s</title>` + pageStyle + `</head><body><h1>%s</h1><p>%s</p></body></html>`
