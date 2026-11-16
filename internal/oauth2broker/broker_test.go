package oauth2broker

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/config"
	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

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
	RegisterRoutes(engine, cfg, s, keys, srv.URL)
	cfg.App.URL = srv.URL
	return srv
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
	if err := requireCLIRedirect(OOBRedirectURI); err != nil {
		t.Errorf("requireCLIRedirect(OOB): %v", err)
	}
}
