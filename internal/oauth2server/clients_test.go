package oauth2server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/config"
	"github.com/infrapi/kayra/internal/store"
)

func newTestServer(t *testing.T, o config.OAuth2ServerConfig) *Server {
	t.Helper()
	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return &Server{cfg: o, store: s, prefix: "test/oauth2", issuer: "https://kayra.example.com", docs: map[string]cachedDoc{},
		HTTPClient: &http.Client{Timeout: time.Second}}
}

// A Client ID Metadata Document: fetched from a trusted host, its
// client_id the URL, cached; any other host, or a document lying about
// itself, refused.
func TestMetadataDocument(t *testing.T) {
	var doc map[string]any
	fetches := 0
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(tls.Close)
	host := strings.TrimPrefix(tls.URL, "https://")
	hostname := host[:strings.LastIndex(host, ":")]
	srv := newTestServer(t, config.OAuth2ServerConfig{MetadataDocumentHosts: []string{hostname}})
	srv.HTTPClient = tls.Client()
	id := tls.URL + "/client.json"

	doc = map[string]any{"client_id": id, "client_name": "Claude", "redirect_uris": []string{"https://claude.example.com/callback"}}
	c, err := srv.client(id)
	if err != nil || c.Name != "Claude" || !c.matchRedirect("https://claude.example.com/callback") || c.matchRedirect("https://evil.example.com/callback") {
		t.Fatalf("client: %+v %v", c, err)
	}
	if _, err := srv.client(id); err != nil || fetches != 1 {
		t.Fatalf("not cached: %d fetches, %v", fetches, err)
	}

	for name, d := range map[string]map[string]any{
		"another client_id": {"client_id": tls.URL + "/other.json", "client_name": "x", "redirect_uris": []string{"https://x.example.com/cb"}},
		"no redirect_uris":  {"client_id": tls.URL + "/b.json", "client_name": "x"},
		"http redirect":     {"client_id": tls.URL + "/c.json", "client_name": "x", "redirect_uris": []string{"http://x.example.com/cb"}},
		"a secret client":   {"client_id": tls.URL + "/d.json", "client_name": "x", "redirect_uris": []string{"https://x.example.com/cb"}, "token_endpoint_auth_method": "client_secret_basic"},
	} {
		doc = d
		target := d["client_id"].(string)
		if name == "another client_id" {
			target = tls.URL + "/a.json"
		}
		if _, err := srv.client(target); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	untrusted := newTestServer(t, config.OAuth2ServerConfig{MetadataDocumentHosts: []string{"claude.ai"}})
	untrusted.HTTPClient = tls.Client()
	if _, err := untrusted.client(id); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Errorf("an untrusted host: %v", err)
	}
	if _, err := srv.client("https://" + host); err == nil {
		t.Error("a client_id without a path: accepted")
	}
}

func TestHostsAndRedirects(t *testing.T) {
	for host, want := range map[string]bool{"claude.ai": true, "CLAUDE.AI": true, "api.anthropic.com": true, "anthropic.com": false, "evil.ai": false} {
		if got := hostAllowed(host, []string{"claude.ai", "*.anthropic.com"}); got != want {
			t.Errorf("%s: %v", host, got)
		}
	}
	c := client{RedirectURIs: []string{"http://127.0.0.1/callback", "https://app.example.com/cb"}}
	for uri, want := range map[string]bool{
		"http://127.0.0.1:43210/callback": true, "http://127.0.0.1/callback": true, "https://app.example.com/cb": true,
		"http://127.0.0.1:43210/other": false, "http://localhost:43210/callback": false, "https://app.example.com:8443/cb": false,
		"https://app.example.com/cb?x=1": false,
	} {
		if got := c.matchRedirect(uri); got != want {
			t.Errorf("%s: %v", uri, got)
		}
	}
}

// RFC 7591: a public client, its redirect URIs loopback or on the hosts.
func TestRegister(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv := newTestServer(t, config.OAuth2ServerConfig{DynamicRegistration: config.DynamicRegistrationConfig{Enabled: true, Hosts: []string{"claude.ai"}}})
	engine := gin.New()
	srv.RegisterRoutes(engine)
	reg := func(body map[string]any) (int, map[string]any) {
		data, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/oauth2/register", bytes.NewReader(data)))
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	code, out := reg(map[string]any{"client_name": "Claude", "redirect_uris": []string{"https://claude.ai/api/mcp/auth_callback"}})
	if code != http.StatusCreated || !strings.HasPrefix(out["client_id"].(string), "dyn-") || out["token_endpoint_auth_method"] != "none" {
		t.Fatalf("register: %d %v", code, out)
	}
	c, err := srv.client(out["client_id"].(string))
	if err != nil || c.Name != "Claude" {
		t.Fatalf("registered: %+v %v", c, err)
	}
	if code, _ := reg(map[string]any{"redirect_uris": []string{"http://127.0.0.1/cb"}}); code != http.StatusCreated {
		t.Errorf("loopback: %d", code)
	}
	for name, body := range map[string]map[string]any{
		"another host":  {"redirect_uris": []string{"https://evil.example.com/cb"}},
		"http":          {"redirect_uris": []string{"http://claude.ai/cb"}},
		"none":          {"client_name": "x"},
		"secret client": {"redirect_uris": []string{"https://claude.ai/cb"}, "token_endpoint_auth_method": "client_secret_post"},
	} {
		if code, out := reg(body); code != http.StatusBadRequest {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
}
