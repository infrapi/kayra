// Package oauth2broker lets `kayra-cli login` (cmd/cli — the
// portable, end-user client, running on someone's laptop with no
// local config of its own) complete a browser-based OAuth2
// Authorization Code + PKCE login against a provider that will never
// allowlist a loopback redirect_uri (http://127.0.0.1:PORT/callback)
// — most enterprise IdPs, Okta included, refuse to register one for
// security policy reasons. Kayra's own public URL is the one
// address the provider *does* allowlist, so Kayra stands in as a
// pure relay: the CLI's own PKCE challenge/state/redirect_uri pass
// straight through unchanged, and Kayra never needs (or requests)
// its own client secret — the provider's real client_id stays the
// exact same public, PKCE-only registration
// `authentifications.<name>.remote.oauth2` already configures. Only
// the redirect_uri the provider itself sees changes: Kayra's own
// /oauth2/v1/callback instead of a loopback address — the same role
// OpenShift's own OAuth server plays in front of its configured
// identity providers for `oc login`.
//
// The CLI never names a provider at all — see
// configuredOAuth2Providers/handleAuthorize, which resolve one
// automatically (or walk the human through a chooser when there's
// more than one configured) — and never reads local config, so
// handleCallback additionally relays the chosen provider's own public
// token_endpoint and client_id back to it: everything
// oauth2login.LoginToServer needs to finish the PKCE exchange itself,
// with zero prior knowledge of the provider. Kayra could never run
// that exchange on the CLI's behalf either way — the code_verifier
// backing code_challenge never leaves the CLI process.
package oauth2broker

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/config"
	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/oauth2login"
	"github.com/infrapi/kayra/internal/oidc"
	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// stateTTL bounds how long an in-flight login can sit idle at the
// provider's own login page before Kayra forgets it: generous enough
// for a human to actually log in, short enough that an abandoned
// attempt doesn't linger in the store forever.
const stateTTL = 10 * time.Minute

// pending is what's stashed between /authorize/continue and /callback
// for one in-flight login — the CLI's own loopback redirect_uri/state,
// so the final bounce-back can reach the right local listener with the
// right state, exactly as if the CLI had talked to the provider
// directly. TokenEndpoint/ClientID are the chosen provider's own public
// OAuth2 client metadata (never a secret — this is a PKCE-only public
// client registration), relayed back to the CLI at /callback so that
// `kayra-cli login` — which never reads local config and never names
// a provider — can still finish the PKCE exchange itself, directly
// against the provider (see oauth2login.LoginToServer). Kayra itself
// can never do that exchange on the CLI's behalf: the code_verifier
// backing code_challenge never leaves the CLI. ApiDomain is this
// instance's own resolved app.api_domain, relayed the same way so
// `kayra-cli login` can save it into the context it writes — every
// later `can-i`/verb command reads it back from there instead of
// guessing "example.com".
type pending struct {
	RedirectURI   string `json:"redirect_uri"`
	State         string `json:"state"`
	TokenEndpoint string `json:"token_endpoint"`
	ClientID      string `json:"client_id"`
	ApiDomain     string `json:"api_domain"`
}

// RegisterRoutes mounts the three routes one CLI oauth2-login round
// trip needs. Unauthenticated by design — this *is* the login flow,
// the same way oidc.RegisterRoutes' discovery endpoints are. baseURL is
// this instance's own resolved public URL — the same value
// oidc.RegisterRoutes is given, never cfg.App.URL's raw YAML value
// directly, so both land on the one address a provider's app
// registration actually allowlists. apiDomain is this instance's own
// already-resolved app.api_domain (apiserver.Build's own
// "" -> "example.com" fallback already applied) — see pending.ApiDomain.
func RegisterRoutes(r gin.IRouter, cfg *config.Config, s store.Store, keys store.Keys, baseURL, apiDomain string) {
	r.GET("/oauth2/v1/authorize", func(c *gin.Context) { handleAuthorize(c, cfg) })
	r.GET("/oauth2/v1/authorize/continue", func(c *gin.Context) { handleContinue(c, cfg, s, keys, baseURL, apiDomain) })
	r.GET("/oauth2/v1/callback", func(c *gin.Context) { handleCallback(c, s, keys) })
}

// authorizeParams is what both /authorize and /authorize/continue parse
// out of the CLI-built URL — the same query string carries over from
// one to the other via the confirmation (or chooser) page's own link.
// Provider is never set by the incoming /authorize request itself —
// `kayra-cli login` (the only client) never names one; handleAuthorize
// always resolves it from cfg before building the confirmation/chooser
// link onward, so by the time /authorize/continue parses this same
// struct, Provider is always present (and always one Kayra itself
// put there).
type authorizeParams struct {
	Provider            string
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// query re-encodes p — used to build both the confirmation page's link
// to /authorize/continue and each option's link on the provider
// chooser page, always from the parsed/resolved struct rather than
// reusing the original request's raw query string, so an
// auto-resolved or chooser-picked Provider is always included exactly
// once.
func (p authorizeParams) query() string {
	return url.Values{
		"provider":              {p.Provider},
		"redirect_uri":          {p.RedirectURI},
		"state":                 {p.State},
		"code_challenge":        {p.CodeChallenge},
		"code_challenge_method": {p.CodeChallengeMethod},
	}.Encode()
}

// parseAuthorizeParams returns a ready-to-send *liberrors.Error (origin
// is the calling handler's) when the CLI-built query is unusable.
func parseAuthorizeParams(c *gin.Context, origin string) (authorizeParams, *liberrors.Error) {
	p := authorizeParams{
		Provider:            c.Query("provider"),
		RedirectURI:         c.Query("redirect_uri"),
		State:               c.Query("state"),
		CodeChallenge:       c.Query("code_challenge"),
		CodeChallengeMethod: c.Query("code_challenge_method"),
	}
	if p.RedirectURI == "" || p.State == "" || p.CodeChallenge == "" {
		return p, liberrors.New(http.StatusBadRequest, origin, "redirect_uri, state and code_challenge are all required").
			WithSolution("start the login with `kayra-cli login` rather than opening this URL by hand")
	}
	if p.CodeChallengeMethod != "S256" {
		return p, liberrors.New(http.StatusBadRequest, origin, "code_challenge_method must be S256")
	}
	if err := requireCLIRedirect(p.RedirectURI); err != nil {
		return p, liberrors.Wrap(err, http.StatusBadRequest, origin, "")
	}
	return p, nil
}

// configuredOAuth2Providers lists every authentifications.<name> that
// configures remote.oauth2, sorted for stable chooser-page output.
func configuredOAuth2Providers(cfg *config.Config) []string {
	var names []string
	for name, p := range cfg.Authentifications {
		if p.Remote != nil && p.Remote.OAuth2 != nil {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// requireCLIRedirect enforces RFC 8252 §7.3: a native/public
// client's redirect_uri must be a loopback IP literal (127.0.0.1 or
// [::1]), never a hostname (DNS can be hijacked) and never an arbitrary
// external URL. This is the one thing standing between this broker and
// becoming an open redirect to anywhere an attacker likes: without it,
// a crafted /oauth2/v1/authorize?...&redirect_uri=https://evil.example
// link would walk a victim through a genuine Okta login and then hand
// the resulting authorization code to evil.example instead of the real
// CLI. The one other value accepted is oauth2login.OOBRedirectURI
// (`kayra-cli login --no-browser`), which redirects nowhere at all —
// handleCallback shows the code to the user instead.
func requireCLIRedirect(raw string) error {
	if raw == oauth2login.OOBRedirectURI {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect_uri: %w", err)
	}
	if u.Scheme != "http" {
		return fmt.Errorf("redirect_uri must use http")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("redirect_uri must be a loopback address (127.0.0.1 or [::1]), got %q", u.Hostname())
	}
	return nil
}

func providerOAuth2Config(cfg *config.Config, name string) (config.AuthProvider, error) {
	provider, ok := cfg.Authentifications[name]
	if !ok || provider.Remote == nil || provider.Remote.OAuth2 == nil {
		return config.AuthProvider{}, fmt.Errorf("provider %q is not configured for oauth2 login (authentifications.%[1]s.remote.oauth2)", name)
	}
	return provider, nil
}

// handleAuthorize renders the one-button confirmation page — no
// username/password fallback by design: the only way through this page
// is onward to the provider's own real login. The caller (`kayra
// login`, the only client there is) never names a provider at all —
// it's always resolved here instead: straight through when exactly
// one is configured, or a chooser page first when there's more than
// one to pick from.
func handleAuthorize(c *gin.Context, cfg *config.Config) {
	const origin = "oauth2broker.Authorize"
	p, lerr := parseAuthorizeParams(c, origin)
	if lerr != nil {
		httpapi.Fail(c, lerr)
		return
	}

	switch names := configuredOAuth2Providers(cfg); len(names) {
	case 0:
		httpapi.Fail(c, liberrors.New(http.StatusBadGateway, origin, "no authentifications.<name>.remote.oauth2 provider is configured on this server").
			WithSolution("ask the Kayra operator to configure an OAuth2 login provider"))
		return
	case 1:
		p.Provider = names[0]
	default:
		renderProviderChooser(c, p, names)
		return
	}

	// Built from the parsed/resolved struct, never the request's raw
	// query string — p.Provider may have just been resolved above and
	// wasn't on the incoming URL at all. html.EscapeString still
	// applies on top: continueURL's query values (state,
	// code_challenge, ...) are attacker-influenced input this response
	// reflects back verbatim otherwise.
	continueURL := html.EscapeString("/oauth2/v1/authorize/continue?" + p.query())
	providerName := html.EscapeString(p.Provider)
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, confirmPageHTML, continueURL, providerName, providerName)
}

// renderProviderChooser is shown only to the agnostic `kayra-cli login`
// flow when Kayra configures more than one remote.oauth2 provider
// and so can't silently pick one on the caller's behalf — each button
// carries p's own query through unchanged, plus that option's
// provider.
// renderProviderChooser links each option straight to
// /oauth2/v1/authorize/continue — the confirmation page's own link —
// rather than back through /authorize: picking a provider off this
// page *is* the explicit, deliberate choice the confirmation page
// otherwise exists to collect (its single "<provider>"
// button, shown only when there was never anything to choose between),
// so routing back through it here would just be a second click
// confirming the first.
func renderProviderChooser(c *gin.Context, p authorizeParams, names []string) {
	var buttons strings.Builder
	for _, name := range names {
		option := p
		option.Provider = name
		href := html.EscapeString("/oauth2/v1/authorize/continue?" + option.query())
		fmt.Fprintf(&buttons, `<a class="btn" href="%s">%s</a>`, href, html.EscapeString(name))
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, chooserPageHTML, buttons.String())
}

// handleContinue stashes the CLI's own redirect_uri/state and 302s the
// browser on to the provider's real authorization endpoint, with
// Kayra's own callback as redirect_uri (never the CLI's loopback —
// the provider will never allowlist that) and the CLI's own
// code_challenge passed straight through unchanged, so the CLI's own
// code_verifier (never seen by Kayra) still verifies at the final
// token exchange.
func handleContinue(c *gin.Context, cfg *config.Config, s store.Store, keys store.Keys, baseURL, apiDomain string) {
	const origin = "oauth2broker.Continue"
	p, lerr := parseAuthorizeParams(c, origin)
	if lerr != nil {
		httpapi.Fail(c, lerr)
		return
	}
	if p.Provider == "" {
		httpapi.Fail(c, liberrors.New(http.StatusBadRequest, origin, "provider is required"))
		return
	}
	provider, err := providerOAuth2Config(cfg, p.Provider)
	if err != nil {
		httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, origin, ""))
		return
	}

	doc, err := oidc.FetchDiscovery(provider.Remote.URL, provider.Remote.Proxy)
	if err != nil {
		httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadGateway, origin+".FetchDiscovery", "could not reach login provider %q", p.Provider).
			WithRetryable(true))
		return
	}
	if doc.AuthorizationEndpoint == "" {
		httpapi.Fail(c, liberrors.New(http.StatusBadGateway, origin, "login provider %q has no authorization_endpoint", p.Provider))
		return
	}

	id, err := randomID()
	if err != nil {
		httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin+".randomID", ""))
		return
	}
	data, err := json.Marshal(pending{
		RedirectURI:   p.RedirectURI,
		State:         p.State,
		TokenEndpoint: doc.TokenEndpoint,
		ClientID:      provider.Remote.OAuth2.ClientID,
		ApiDomain:     apiDomain,
	})
	if err != nil {
		httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin+".Marshal", ""))
		return
	}
	if err := s.PutTTL(keys.OAuth2BrokerState(id), data, stateTTL); err != nil {
		httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin+".PutTTL", ""))
		return
	}

	scopes := provider.Remote.OAuth2.Scopes
	if len(scopes) == 0 {
		scopes = oauth2login.DefaultScopes
	}

	authorizeURL, err := url.Parse(doc.AuthorizationEndpoint)
	if err != nil {
		httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadGateway, origin, "login provider %q advertises an invalid authorization_endpoint", p.Provider))
		return
	}
	authorizeURL.RawQuery = url.Values{
		"client_id":             {provider.Remote.OAuth2.ClientID},
		"redirect_uri":          {callbackURL(baseURL)},
		"response_type":         {"code"},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {id},
		"code_challenge":        {p.CodeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	c.Redirect(http.StatusFound, authorizeURL.String())
}

// handleCallback is the provider's own redirect target: look up the
// in-flight login by the broker-generated state (one-time use — it's
// deleted immediately, win or lose), then bounce the browser the rest
// of the way to the CLI's own local listener with the provider's
// code/error and the CLI's own original state — indistinguishable, from
// the CLI's own callback handler's perspective, from the provider
// having redirected there directly.
func handleCallback(c *gin.Context, s store.Store, keys store.Keys) {
	const origin = "oauth2broker.Callback"
	id := c.Query("state")
	if id == "" {
		httpapi.Fail(c, liberrors.New(http.StatusBadRequest, origin, "callback carried no state"))
		return
	}

	data, err := s.Get(keys.OAuth2BrokerState(id))
	if err != nil {
		httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, origin+".Get", "unknown or expired login attempt").
			WithSolution("run `kayra-cli login` again"))
		return
	}
	_ = s.Delete(keys.OAuth2BrokerState(id))

	var pend pending
	if err := json.Unmarshal(data, &pend); err != nil {
		httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin+".Unmarshal", ""))
		return
	}
	// Defense in depth: re-check even though handleContinue already
	// enforced this before ever storing pend — nothing on this path
	// should ever redirect anywhere but back to a loopback address.
	if err := requireCLIRedirect(pend.RedirectURI); err != nil {
		httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin, ""))
		return
	}
	if pend.RedirectURI == oauth2login.OOBRedirectURI {
		renderLoginCode(c, pend)
		return
	}

	target, err := url.Parse(pend.RedirectURI)
	if err != nil {
		httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin, ""))
		return
	}

	q := url.Values{"state": {pend.State}}
	if errParam := c.Query("error"); errParam != "" {
		q.Set("error", errParam)
		q.Set("error_description", c.Query("error_description"))
	} else {
		code := c.Query("code")
		if code == "" {
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, origin, "provider callback carried no code"))
			return
		}
		q.Set("code", code)
		// Public, non-secret OAuth2 client metadata for the provider
		// this login just went through — relayed back so a fully
		// agnostic caller (oauth2login.LoginToServer) can finish the
		// PKCE exchange itself without ever having been told which
		// provider it was, or reading any local config.
		q.Set("token_endpoint", pend.TokenEndpoint)
		q.Set("client_id", pend.ClientID)
		q.Set("api_domain", pend.ApiDomain)
	}
	target.RawQuery = q.Encode()

	c.Redirect(http.StatusFound, target.String())
}

// renderLoginCode ends a `kayra-cli login --no-browser` attempt: no
// local listener exists to redirect to, so the browser is shown the
// oauth2login.LoginCode the loopback redirect would otherwise have
// carried, for the user to paste into the terminal that is waiting for
// it (see oauth2login.LoginToServerManual). Never cached or leaked via
// Referer: the code is single-use and only redeemable with that
// terminal's own PKCE verifier, but there is still no reason for it to
// outlive this page.
func renderLoginCode(c *gin.Context, pend pending) {
	const origin = "oauth2broker.Callback"
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")

	if errParam := c.Query("error"); errParam != "" {
		msg := errParam
		if desc := c.Query("error_description"); desc != "" {
			msg += ": " + desc
		}
		httpapi.Fail(c, liberrors.New(http.StatusBadRequest, origin, "login provider denied the login: %s", msg).
			WithSolution("run `kayra-cli login --no-browser` again"))
		return
	}
	code := c.Query("code")
	if code == "" {
		httpapi.Fail(c, liberrors.New(http.StatusBadRequest, origin, "provider callback carried no code"))
		return
	}

	loginCode, err := oauth2login.EncodeLoginCode(oauth2login.LoginCode{
		Code:          code,
		State:         pend.State,
		TokenEndpoint: pend.TokenEndpoint,
		ClientID:      pend.ClientID,
		ApiDomain:     pend.ApiDomain,
	})
	if err != nil {
		httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin+".EncodeLoginCode", ""))
		return
	}
	// base64url only — nothing to escape, but escape anyway.
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, loginCodePageHTML, html.EscapeString(loginCode))
}

// callbackURL is Kayra's own redirect_uri — must byte-for-byte match
// what oauth2login.LoginToServer later sends as RedirectURL on its
// token exchange, since the provider checks that string against what
// was actually used at /authorize (RFC 6749 §4.1.3). baseURL is this
// instance's own resolved app.url; LoginToServer derives the identical
// string from --server (strings.TrimRight + "/oauth2/v1/callback"),
// with no config to read it from at all.
func callbackURL(baseURL string) string {
	return strings.TrimRight(baseURL, "/") + "/oauth2/v1/callback"
}

func randomID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth2broker: generate id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

const confirmPageHTML = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Kayra login</title>
<style>
body{font-family:system-ui,sans-serif;background:#0b0d12;color:#e6e6e6;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#151821;border:1px solid #2a2f3a;border-radius:12px;padding:2.5rem 3rem;text-align:center;max-width:380px}
h1{font-size:1.1rem;font-weight:600;margin:0 0 1.5rem}
a.btn{display:inline-block;background:#3b82f6;color:#fff;text-decoration:none;padding:.7rem 1.6rem;border-radius:8px;font-weight:600}
a.btn:hover{background:#2563eb}
p{color:#8a8f98;font-size:.85rem;margin-top:1.5rem}
</style>
</head>
<body>
  <div class="card">
    <h1>Log in with</h1>
    <a class="btn" href="%s">%s</a>
    <p>You will be redirected to %s to sign in.</p>
  </div>
</body>
</html>
`

// chooserPageHTML is shown only when Kayra configures more than one
// remote.oauth2 provider and the caller (kayra-cli login) named none —
// %s is the pre-built, already-escaped sequence of <a class="btn">
// buttons from renderProviderChooser.
const chooserPageHTML = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Kayra login</title>
<style>
body{font-family:system-ui,sans-serif;background:#0b0d12;color:#e6e6e6;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#151821;border:1px solid #2a2f3a;border-radius:12px;padding:2.5rem 3rem;text-align:center;max-width:380px}
h1{font-size:1.1rem;font-weight:600;margin:0 0 1.5rem}
.buttons{display:flex;flex-direction:column;gap:.6rem}
a.btn{display:inline-block;background:#3b82f6;color:#fff;text-decoration:none;padding:.7rem 1.6rem;border-radius:8px;font-weight:600}
a.btn:hover{background:#2563eb}
</style>
</head>
<body>
  <div class="card">
    <h1>kayra-cli login</h1>
    <div class="buttons">%s</div>
  </div>
</body>
</html>
`

// loginCodePageHTML is renderLoginCode's success page — %s is the
// already-escaped login code.
const loginCodePageHTML = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Kayra login code</title>
<style>
body{font-family:system-ui,sans-serif;background:#0b0d12;color:#e6e6e6;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:1rem;box-sizing:border-box}
.card{background:#151821;border:1px solid #2a2f3a;border-radius:12px;padding:2rem;text-align:center;max-width:560px;width:100%%}
h1{font-size:1.1rem;font-weight:600;margin:0 0 1rem}
textarea{width:100%%;box-sizing:border-box;height:7rem;background:#0b0d12;color:#e6e6e6;border:1px solid #2a2f3a;border-radius:8px;padding:.6rem;font-family:ui-monospace,monospace;font-size:.8rem;resize:none;word-break:break-all}
button{margin-top:1rem;background:#3b82f6;color:#fff;border:0;padding:.7rem 1.6rem;border-radius:8px;font-weight:600;cursor:pointer}
button:hover{background:#2563eb}
p{color:#8a8f98;font-size:.85rem;margin-top:1.2rem}
p.warn{color:#f0b429}
</style>
</head>
<body>
  <div class="card">
    <h1>Paste this code into your terminal</h1>
    <textarea id="code" readonly onclick="this.select()">%s</textarea>
    <button type="button" onclick="var t=document.getElementById('code');t.select();navigator.clipboard&&navigator.clipboard.writeText(t.value);this.textContent='Copied'">Copy</button>
    <p>Paste it at the <code>kayra-cli login --no-browser</code> prompt. It works once, only in that terminal, for the next few minutes.</p>
    <p class="warn">Only paste it into a terminal where you started this login yourself. Never send it to anyone.</p>
  </div>
</body>
</html>
`
