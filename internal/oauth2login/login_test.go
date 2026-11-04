package oauth2login

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// fakeIDP serves just enough of a real OIDC provider for a broker-relayed
// Authorization Code + PKCE round trip to run against it: discovery, an
// authorization endpoint that immediately redirects back to whatever
// redirect_uri it was given (carrying a fixed code and the caller's own
// state, exactly like a user who just approved the login would produce),
// and a token endpoint that only succeeds when both the redirect_uri it
// receives matches wantRedirectURI exactly (RFC 6749 §4.1.3 — proving
// LoginToServer's final exchange claims the broker's own callback, never
// this CLI's own loopback address) and the code_verifier it receives
// actually hashes (S256) to the code_challenge the authorize call carried
// (proving LoginToServer generates a genuine PKCE pair, not just passes
// some string through).
func fakeIDP(t *testing.T, wantRedirectURI *string) *httptest.Server {
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
		if wantRedirectURI != nil && *wantRedirectURI != "" && r.FormValue("redirect_uri") != *wantRedirectURI {
			http.Error(w, "redirect_uri does not match what /authorize was called with", http.StatusBadRequest)
			return
		}

		sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
		gotChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
		if gotChallenge != challenge {
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

// asBrowser swaps OpenBrowser for a double that fetches authURL itself
// (following redirects, Go's http.Client default) instead of actually
// launching a browser — enough to drive the whole relayed round trip,
// since every hop in between (broker, idp) answers with an HTTP
// redirect, ending at LoginToServer's own local callback listener.
func asBrowser(t *testing.T) {
	t.Helper()
	orig := OpenBrowser
	OpenBrowser = func(authURL string) error {
		go func() {
			resp, err := http.Get(authURL)
			if err != nil {
				t.Logf("browser double: %v", err)
				return
			}
			resp.Body.Close()
		}()
		return nil
	}
	t.Cleanup(func() { OpenBrowser = orig })
}

// fakeAgnosticBroker stands in for oauth2broker's /oauth2/v1/authorize
// and /oauth2/v1/callback exactly as `kayra login` sees them: no
// provider is ever named on the way in, and the callback relays back
// a fixed token_endpoint/client_id alongside the code — the one extra
// contract LoginToServer depends on that Login doesn't. Which
// provider actually gets picked (auto-selected, or via a chooser page)
// is oauth2broker's own concern, with its own full test suite (see
// internal/oauth2broker) — this only drives LoginToServer's half.
func fakeAgnosticBroker(t *testing.T, idpAuthorizeURL, tokenEndpoint, clientID string) *httptest.Server {
	t.Helper()

	type stashed struct{ redirectURI, state string }
	pending := map[string]stashed{}

	var broker *httptest.Server
	mux := http.NewServeMux()
	broker = httptest.NewServer(mux)
	t.Cleanup(broker.Close)

	mux.HandleFunc("/oauth2/v1/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("provider") != "" {
			http.Error(w, "kayra login must never send a provider", http.StatusBadRequest)
			return
		}
		brokerState := "broker-" + q.Get("state")
		pending[brokerState] = stashed{redirectURI: q.Get("redirect_uri"), state: q.Get("state")}

		target, err := url.Parse(idpAuthorizeURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		target.RawQuery = url.Values{
			"redirect_uri":          {broker.URL + "/oauth2/v1/callback"},
			"state":                 {brokerState},
			"code_challenge":        {q.Get("code_challenge")},
			"code_challenge_method": {q.Get("code_challenge_method")},
		}.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
	})

	mux.HandleFunc("/oauth2/v1/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		p, ok := pending[q.Get("state")]
		if !ok {
			http.Error(w, "unknown broker state", http.StatusBadRequest)
			return
		}
		target, _ := url.Parse(p.redirectURI)
		target.RawQuery = url.Values{
			"code":           {q.Get("code")},
			"state":          {p.state},
			"token_endpoint": {tokenEndpoint},
			"client_id":      {clientID},
		}.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
	})

	return broker
}

func TestLoginToServerRunsFullFlowThroughBroker(t *testing.T) {
	var wantRedirectURI string
	idp := fakeIDP(t, &wantRedirectURI)
	fb := fakeAgnosticBroker(t, idp.URL+"/authorize", idp.URL+"/token", "test-client")
	wantRedirectURI = fb.URL + "/oauth2/v1/callback"

	asBrowser(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := LoginToServer(ctx, fb.URL, io.Discard)
	if err != nil {
		t.Fatalf("LoginToServer: %v", err)
	}
	if result.AccessToken != "real-access-token" {
		t.Fatalf("AccessToken = %q, want real-access-token", result.AccessToken)
	}
	if result.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q, want Bearer", result.TokenType)
	}
}

func TestLoginToServerRequiresServer(t *testing.T) {
	if _, err := LoginToServer(context.Background(), "", io.Discard); err == nil {
		t.Fatalf("LoginToServer: want error for an empty server")
	}
}

// TestLoginToServerFailsWithoutTokenEndpoint covers an old broker that
// predates `kayra login`'s relay contract (or a bug in a new one): it
// approves the login but never hands back a token_endpoint/client_id,
// which LoginToServer has no other way to learn — it must fail loudly
// rather than attempt the exchange with nothing to exchange against.
func TestLoginToServerFailsWithoutTokenEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	broker := httptest.NewServer(mux)
	t.Cleanup(broker.Close)

	mux.HandleFunc("/oauth2/v1/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		redirect, _ := url.Parse(q.Get("redirect_uri"))
		redirect.RawQuery = url.Values{"code": {"fake-code"}, "state": {q.Get("state")}}.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})

	asBrowser(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := LoginToServer(ctx, broker.URL, io.Discard); err == nil {
		t.Fatalf("LoginToServer: want error when the callback carries no token_endpoint/client_id")
	}
}

// TestLoginToServerFailsOnProviderDenial confirms LoginToServer's local
// callback handler surfaces a provider-reported denial as an error,
// regardless of which hop produced it.
func TestLoginToServerFailsOnProviderDenial(t *testing.T) {
	mux := http.NewServeMux()
	broker := httptest.NewServer(mux)
	t.Cleanup(broker.Close)

	mux.HandleFunc("/oauth2/v1/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		redirect, _ := url.Parse(q.Get("redirect_uri"))
		redirect.RawQuery = url.Values{
			"error":             {"access_denied"},
			"error_description": {"user said no"},
			"state":             {q.Get("state")},
		}.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})

	asBrowser(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := LoginToServer(ctx, broker.URL, io.Discard); err == nil {
		t.Fatalf("LoginToServer: want error when the provider reports access_denied")
	}
}
