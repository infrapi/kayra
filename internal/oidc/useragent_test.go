package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/infrapi/lib/pkg/useragent"
)

// A provider's documents are fetched with Kayra named in the User-Agent,
// directly and through a proxy: the provider's, or the proxy's, logs tell
// who called.
func TestFetchNamesKayraInTheUserAgent(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.UserAgent())
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"issuer":"https://idp.example.com","jwks_uri":"https://idp.example.com/keys"}`)); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	if _, err := FetchDiscovery(srv.URL+"/.well-known/openid-configuration", ""); err != nil {
		t.Fatalf("FetchDiscovery: %v", err)
	}
	if _, err := FetchDiscovery("http://unroutable.invalid/.well-known/openid-configuration", srv.URL); err != nil {
		t.Fatalf("FetchDiscovery through the proxy: %v", err)
	}
	want := useragent.String()
	if len(got) != 2 || got[0] != want || got[1] != want {
		t.Fatalf("User-Agents = %q, want %q twice", got, want)
	}
}
