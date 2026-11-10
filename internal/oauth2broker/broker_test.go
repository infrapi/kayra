package oauth2broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/config"
	"github.com/infrapi/kayra/internal/oauth2login"
	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// testApiDomain is testBroker's own app.api_domain — deliberately not
// "example.com" (the fallback a server with none configured would use)
// so a test asserting on it can't be fooled by that fallback kicking
// in instead of the real relay (see pending.ApiDomain) actually
// carrying it through.
const testApiDomain = "kayra-test.example"

// fakeIDP serves just enough of a real OIDC provider for a full
// broker-relayed Authorization Code + PKCE round trip: discovery, an
// authorization endpoint that immediately approves (redirecting back
// to whatever redirect_uri it was given — the broker's own callback,
// never the CLI's loopback, since the broker is the one calling this),
// and a token endpoint that only succeeds when the code_verifier it
// receives genuinely hashes (S256) to the code_challenge /authorize
// carried — the CLI's own PKCE pair, passed through this broker
// unchanged.
func fakeIDP(t *testing.T) *httptest.Server {
	t.Helper()

	var challenge string
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srv.URL,
			"jwks_uri":               srv.URL + "/keys",
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		challenge = q.Get("code_challenge")
		if q.Get("code_challenge_method") != "S256" {
			http.Error(w, "want S256 code_challenge_method", http.StatusBadRequest)
			return
		}
		redirect, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			http.Error(w, "bad redirect_uri", http.StatusBadRequest)
			return
		}
		rq := redirect.Query()
		rq.Set("code", "fake-auth-code")
		rq.Set("state", q.Get("state"))
		redirect.RawQuery = rq.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.FormValue("code") != "fake-auth-code" {
			http.Error(w, "unknown code", http.StatusBadRequest)
			return
		}
		sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			http.Error(w, "code_verifier does not match the code_challenge sent to /authorize", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "real-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	return srv
}

func testBroker(t *testing.T, cfg *config.Config) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)

	s, keys, err := store.New(config.DatabaseBackend{Local: &config.LocalConfig{Path: t.TempDir()}})
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	engine := gin.New()
	srv := httptest.NewServer(engine)
	t.Cleanup(srv.Close)

	// Routes can be registered on engine after the server starts —
	// httptest.NewServer just dispatches to engine.ServeHTTP per
	// request, it doesn't snapshot the router tree.
	RegisterRoutes(engine, cfg, s, keys, srv.URL, testApiDomain)
	cfg.App.URL = srv.URL
	return srv
}

var hrefRe = regexp.MustCompile(`href="([^"]+)"`)

// asRealBrowserFollowingLinks behaves like an actual user clicking
// through whatever Kayra's own /oauth2/v1/authorize serves back for
// the agnostic `kayra login` flow: just a single-button confirmation
// page when there's nothing to choose between, or a provider chooser
// page first when Kayra configures more than one — either way it
// just keeps following the first <a href> it finds in each 200
// response until a page has none left (the final loopback
// destination's own "login complete" page).
func asRealBrowserFollowingLinks(t *testing.T, brokerBaseURL string) {
	t.Helper()
	orig := oauth2login.OpenBrowser
	oauth2login.OpenBrowser = func(authURL string) error {
		go func() {
			next := authURL
			for i := 0; i < 5 && next != ""; i++ {
				resp, err := http.Get(next)
				if err != nil {
					t.Logf("browser double: GET %s: %v", next, err)
					return
				}
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()

				m := hrefRe.FindSubmatch(body)
				if m == nil {
					return
				}
				href := html.UnescapeString(string(m[1]))
				if len(href) > 0 && href[0] == '/' {
					href = brokerBaseURL + href
				}
				next = href
			}
		}()
		return nil
	}
	t.Cleanup(func() { oauth2login.OpenBrowser = orig })
}

func TestLoginToServerAutoSelectsSingleProvider(t *testing.T) {
	idp := fakeIDP(t)

	cfg := &config.Config{
		Authentifications: map[string]config.AuthProvider{
			"okta": {
				Remote: &config.RemoteAuthConfig{
					URL:    idp.URL + "/.well-known/openid-configuration",
					OAuth2: &config.OAuth2LoginConfig{ClientID: "test-client"},
				},
			},
		},
	}
	broker := testBroker(t, cfg)
	asRealBrowserFollowingLinks(t, broker.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := oauth2login.LoginToServer(ctx, broker.URL, io.Discard)
	if err != nil {
		t.Fatalf("LoginToServer: %v", err)
	}
	if result.AccessToken != "real-access-token" {
		t.Fatalf("AccessToken = %q, want real-access-token", result.AccessToken)
	}
	if result.ApiDomain != testApiDomain {
		t.Fatalf("ApiDomain = %q, want %q (relayed from the broker's own pending.ApiDomain)", result.ApiDomain, testApiDomain)
	}
}

func TestLoginToServerShowsChooserWithMultipleProviders(t *testing.T) {
	idp := fakeIDP(t)

	cfg := &config.Config{
		Authentifications: map[string]config.AuthProvider{
			"okta": {
				Remote: &config.RemoteAuthConfig{
					URL:    idp.URL + "/.well-known/openid-configuration",
					OAuth2: &config.OAuth2LoginConfig{ClientID: "okta-client"},
				},
			},
			"google": {
				Remote: &config.RemoteAuthConfig{
					URL:    idp.URL + "/.well-known/openid-configuration",
					OAuth2: &config.OAuth2LoginConfig{ClientID: "google-client"},
				},
			},
		},
	}
	broker := testBroker(t, cfg)
	asRealBrowserFollowingLinks(t, broker.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := oauth2login.LoginToServer(ctx, broker.URL, io.Discard)
	if err != nil {
		t.Fatalf("LoginToServer: %v", err)
	}
	if result.AccessToken != "real-access-token" {
		t.Fatalf("AccessToken = %q, want real-access-token", result.AccessToken)
	}
}

func TestAuthorizeChooserPageListsEveryProvider(t *testing.T) {
	cfg := &config.Config{
		Authentifications: map[string]config.AuthProvider{
			"okta":   {Remote: &config.RemoteAuthConfig{OAuth2: &config.OAuth2LoginConfig{ClientID: "c"}}},
			"google": {Remote: &config.RemoteAuthConfig{OAuth2: &config.OAuth2LoginConfig{ClientID: "c"}}},
		},
	}
	broker := testBroker(t, cfg)

	u := broker.URL + "/oauth2/v1/authorize?" + url.Values{
		"redirect_uri":          {"http://127.0.0.1:12345/callback"},
		"state":                 {"s"},
		"code_challenge":        {"c"},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %s", resp.StatusCode, body)
	}
	for _, want := range []string{"okta", "google"} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("chooser page missing provider %q: %s", want, body)
		}
	}
	// Each option must link straight to /authorize/continue, not back
	// through /authorize — picking a provider here is already the
	// deliberate choice; routing back through the single-button
	// confirmation page would just be a second click confirming the
	// first.
	if bytes.Contains(body, []byte(`href="/oauth2/v1/authorize?`)) {
		t.Errorf("chooser page links back through /authorize instead of straight to /authorize/continue: %s", body)
	}
	if !bytes.Contains(body, []byte(`href="/oauth2/v1/authorize/continue?`)) {
		t.Errorf("chooser page options don't link to /authorize/continue: %s", body)
	}
}

func TestAuthorizeNoProviderConfiguredFails(t *testing.T) {
	cfg := &config.Config{Authentifications: map[string]config.AuthProvider{}}
	broker := testBroker(t, cfg)

	u := broker.URL + "/oauth2/v1/authorize?" + url.Values{
		"redirect_uri":          {"http://127.0.0.1:12345/callback"},
		"state":                 {"s"},
		"code_challenge":        {"c"},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 when no provider is configured", resp.StatusCode)
	}
}

func TestAuthorizeRejectsNonLoopbackRedirect(t *testing.T) {
	cfg := &config.Config{
		Authentifications: map[string]config.AuthProvider{
			"okta": {Remote: &config.RemoteAuthConfig{OAuth2: &config.OAuth2LoginConfig{ClientID: "c"}}},
		},
	}
	broker := testBroker(t, cfg)

	u := broker.URL + "/oauth2/v1/authorize?" + url.Values{
		"redirect_uri":          {"https://evil.example/callback"},
		"state":                 {"s"},
		"code_challenge":        {"c"},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a non-loopback redirect_uri (open-redirect guard)", resp.StatusCode)
	}
	// User-visible errors are infrapi/lib problem details, never plain text.
	if ct := resp.Header.Get("Content-Type"); ct != liberrors.MediaType {
		t.Fatalf("Content-Type = %q, want %q", ct, liberrors.MediaType)
	}
	var problem struct {
		Status int    `json:"status"`
		Detail string `json:"detail"`
		Origin string `json:"origin"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Status != http.StatusBadRequest || problem.Origin != "oauth2broker.Authorize" || problem.Detail == "" {
		t.Fatalf("problem = %+v, want status 400, origin oauth2broker.Authorize and a detail", problem)
	}
}

func TestCallbackRejectsUnknownState(t *testing.T) {
	cfg := &config.Config{Authentifications: map[string]config.AuthProvider{}}
	broker := testBroker(t, cfg)

	resp, err := http.Get(broker.URL + "/oauth2/v1/callback?code=x&state=never-issued")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown/expired state", resp.StatusCode)
	}
}

func TestConfirmPageEscapesQueryValues(t *testing.T) {
	cfg := &config.Config{
		Authentifications: map[string]config.AuthProvider{
			"okta": {Remote: &config.RemoteAuthConfig{OAuth2: &config.OAuth2LoginConfig{ClientID: "c"}}},
		},
	}
	broker := testBroker(t, cfg)

	u := broker.URL + "/oauth2/v1/authorize?" + url.Values{
		"redirect_uri":          {"http://127.0.0.1:12345/callback"},
		"state":                 {`"><script>alert(1)</script>`},
		"code_challenge":        {"c"},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %s", resp.StatusCode, body)
	}
	if bytes.Contains(body, []byte("<script>alert(1)</script>")) {
		t.Fatalf("confirmation page reflected an unescaped <script> tag from the query string: %s", body)
	}
}

var (
	authURLRe   = regexp.MustCompile(`(http://\S+/oauth2/v1/authorize\?\S+)`)
	loginCodeRe = regexp.MustCompile(`<textarea[^>]*>([^<]+)</textarea>`)
)

// urlSniffer is the --no-browser flow's stderr: it hands the first
// authorize URL LoginToServerManual prints to urls, as a user reading
// their terminal would.
type urlSniffer struct {
	buf  bytes.Buffer
	urls chan string
	sent bool
}

func (s *urlSniffer) Write(p []byte) (int, error) {
	s.buf.Write(p)
	if m := authURLRe.FindString(s.buf.String()); m != "" && !s.sent {
		s.sent = true
		s.urls <- m
	}
	return len(p), nil
}

// browseToLoginCode plays the user on another machine: follow the
// authorize URL's links through the confirmation page and the provider,
// then read the login code off the broker's final page.
func browseToLoginCode(t *testing.T, brokerBaseURL, authURL string) (code string, resp *http.Response) {
	t.Helper()
	next := authURL
	for i := 0; i < 5; i++ {
		r, err := http.Get(next)
		if err != nil {
			t.Fatalf("browser: GET %s: %v", next, err)
		}
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if m := loginCodeRe.FindSubmatch(body); m != nil {
			return html.UnescapeString(string(m[1])), r
		}
		m := hrefRe.FindSubmatch(body)
		if m == nil {
			t.Fatalf("browser: page has neither a login code nor a link: %s", body)
		}
		href := html.UnescapeString(string(m[1]))
		if href[0] == '/' {
			href = brokerBaseURL + href
		}
		next = href
	}
	t.Fatalf("browser: no login code after following links")
	return "", nil
}

func oktaConfig(idp *httptest.Server) *config.Config {
	return &config.Config{
		Authentifications: map[string]config.AuthProvider{
			"okta": {
				Remote: &config.RemoteAuthConfig{
					URL:    idp.URL + "/.well-known/openid-configuration",
					OAuth2: &config.OAuth2LoginConfig{ClientID: "test-client"},
				},
			},
		},
	}
}

// TestLoginToServerManualRunsFullFlowThroughBroker drives
// `kayra-cli login --no-browser` end to end: the CLI prints a URL, a
// "browser" elsewhere logs in and is shown a login code instead of a
// loopback redirect, and pasting that code into the CLI's stdin
// finishes the same PKCE exchange a loopback login does.
func TestLoginToServerManualRunsFullFlowThroughBroker(t *testing.T) {
	idp := fakeIDP(t)
	broker := testBroker(t, oktaConfig(idp))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stdinR, stdinW := io.Pipe()
	stderr := &urlSniffer{urls: make(chan string, 1)}
	go func() {
		authURL := <-stderr.urls
		code, resp := browseToLoginCode(t, broker.URL, authURL)
		if got := resp.Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("login code page Cache-Control = %q, want no-store", got)
		}
		_, _ = io.WriteString(stdinW, code+"\n")
	}()

	result, err := oauth2login.LoginToServerManual(ctx, broker.URL, stdinR, stderr)
	if err != nil {
		t.Fatalf("LoginToServerManual: %v", err)
	}
	if result.AccessToken != "real-access-token" {
		t.Fatalf("AccessToken = %q, want real-access-token", result.AccessToken)
	}
	if result.ApiDomain != testApiDomain {
		t.Fatalf("ApiDomain = %q, want %q", result.ApiDomain, testApiDomain)
	}
}

// TestLoginToServerManualRejectsCodeFromAnotherLogin confirms a login
// code is bound to the CLI process that started that login: one minted
// for a different attempt (here: a different state) is refused before
// any token exchange is tried.
func TestLoginToServerManualRejectsCodeFromAnotherLogin(t *testing.T) {
	idp := fakeIDP(t)
	broker := testBroker(t, oktaConfig(idp))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	other, err := oauth2login.EncodeLoginCode(oauth2login.LoginCode{
		Code: "fake-auth-code", State: "someone-elses-state",
		TokenEndpoint: idp.URL + "/token", ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("EncodeLoginCode: %v", err)
	}
	_, err = oauth2login.LoginToServerManual(ctx, broker.URL, bytes.NewBufferString(other+"\n"), io.Discard)
	if err == nil {
		t.Fatalf("LoginToServerManual: want error for a login code with another attempt's state")
	}
}

// TestAuthorizeStillRejectsNonLoopbackRedirect guards the open-redirect
// check now that it accepts one non-loopback value: only the exact OOB
// URN gets through, nothing that merely resembles it.
func TestAuthorizeStillRejectsNonLoopbackRedirect(t *testing.T) {
	for _, redirect := range []string{
		"https://evil.example/callback",
		"urn:ietf:wg:oauth:2.0:oob:auto",
		"urn:ietf:wg:oauth:2.0:oob/../evil",
	} {
		if err := requireCLIRedirect(redirect); err == nil {
			t.Errorf("requireCLIRedirect(%q): want error", redirect)
		}
	}
	if err := requireCLIRedirect(oauth2login.OOBRedirectURI); err != nil {
		t.Errorf("requireCLIRedirect(OOB): %v", err)
	}
}
