package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// proxyDouble answers every request it receives with body, regardless of
// the requested host/path — a stand-in for a real forward proxy that lets
// these tests prove traffic was actually routed through it: the target
// host is unroutable.invalid (RFC 2606, guaranteed never to resolve), so a
// successful response can only mean the request reached this double, not
// the (nonexistent) target directly.
func proxyDouble(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchDiscoveryRoutesThroughConfiguredProxy(t *testing.T) {
	proxy := proxyDouble(t, `{"issuer":"https://via-proxy.example","jwks_uri":"https://via-proxy.example/keys"}`)

	doc, err := FetchDiscovery("http://unroutable.invalid/.well-known/openid-configuration", proxy.URL)
	if err != nil {
		t.Fatalf("FetchDiscovery: %v", err)
	}
	if doc.Issuer != "https://via-proxy.example" {
		t.Fatalf("Issuer = %q, want the proxy double's own response", doc.Issuer)
	}
}

func TestFetchJWKSRoutesThroughConfiguredProxy(t *testing.T) {
	proxy := proxyDouble(t, `{"keys":[]}`)

	keys, err := FetchJWKS("http://unroutable.invalid/keys", proxy.URL)
	if err != nil {
		t.Fatalf("FetchJWKS: %v", err)
	}
	if keys == nil {
		t.Fatalf("FetchJWKS: got nil keys, want an empty (but non-nil-error) slice from the proxy double")
	}
}

func TestFetchUserinfoRoutesThroughConfiguredProxy(t *testing.T) {
	proxy := proxyDouble(t, `{"sub":"via-proxy"}`)

	info, err := FetchUserinfo("http://unroutable.invalid/userinfo", "tok", proxy.URL)
	if err != nil {
		t.Fatalf("FetchUserinfo: %v", err)
	}
	if info["sub"] != "via-proxy" {
		t.Fatalf("userinfo = %v, want the proxy double's own response", info)
	}
}

func TestClientForRejectsInvalidProxy(t *testing.T) {
	if _, err := ClientFor("http://[::1"); err == nil {
		t.Fatalf("ClientFor: want error for an unparseable proxy URL")
	}
}

func TestClientForNoProxyReturnsSharedDefaultClient(t *testing.T) {
	c1, err := ClientFor("")
	if err != nil {
		t.Fatalf("ClientFor: %v", err)
	}
	c2, err := ClientFor("")
	if err != nil {
		t.Fatalf("ClientFor: %v", err)
	}
	if c1 != c2 {
		t.Fatalf("ClientFor(\"\") should return the same shared, env-proxy-aware client every time")
	}
}
