// Package oauth2login runs a real browser-based OAuth2 Authorization
// Code + PKCE flow against a remote provider (Okta, say) — the same
// flow `oc login` runs against OpenShift's own /oauth/authorize. Most
// enterprise IdPs, Okta included, will never allowlist a CLI's own
// loopback redirect_uri (http://127.0.0.1:PORT/callback) for security
// policy reasons, so this never talks to the provider's authorization
// endpoint directly: it opens the browser at Kayra's own
// /oauth2/v1/authorize instead (see internal/oauth2broker, which is
// what the provider's app registration actually allowlists), and that
// relays the real flow back here unchanged once it completes — Kayra
// never sees this CLI's own PKCE verifier, and the final code→token
// exchange below still happens directly against the provider, exactly
// as if there were no relay in between.
//
// This is `kayra login`'s entire flow: a plain end user on their own
// laptop who knows only a server URL, never a provider name, and never
// reads any local config at all. The broker resolves which provider to
// use entirely on its own (see oauth2broker.handleAuthorize) and hands
// back that provider's own (public, non-secret) token endpoint/client_id
// at the very end, in the loopback callback itself, just in time to
// finish the exchange below. This is CLI-only; the API server never
// runs this half of the flow — it only ever verifies tokens the
// provider already issued.
package oauth2login

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/infrapi/kayra/internal/oidc"
)

// DefaultScopes is requested when a provider's
// authentifications.<name>.remote.oauth2.scopes is empty.
var DefaultScopes = []string{"openid", "profile", "email"}

// callbackPath is where the local loopback server catches the
// provider's redirect; must match what's registered as this client's
// redirect_uri in the provider's own OAuth2 app configuration (modulo
// the random port, most providers allow any 127.0.0.1 port for a
// "native"/public client redirect_uri, exactly like oc/kubectl's own
// OIDC plugins).
const callbackPath = "/callback"

// Result is a completed login's outcome — AccessToken is what a caller
// uses as this request's bearer token against Kayra's own API (and
// against the provider's userinfo endpoint, for a claims-backed
// authorizations.<name> entry).
type Result struct {
	AccessToken string
	TokenType   string
	Expiry      time.Time
}

// OpenBrowser is swappable for tests — both this package's own and
// internal/oauth2broker's integration tests, which simulate a user
// clicking through the real confirmation/chooser page without an
// actual display. In production it best-effort launches the user's
// default browser; LoginToServer never depends on this succeeding —
// stderr always also receives the URL to open by hand.
var OpenBrowser = defaultOpenBrowser

// LoginToServer is `kayra login`'s entire flow: a plain end user on
// their own laptop who knows nothing but a Kayra server URL — no
// provider name, no discovery URL, no client_id, and no local
// kayra.yaml to read any of that from. It asks serverBaseURL's own
// broker to pick a provider on its behalf (see
// oauth2broker.handleAuthorize — automatic when exactly one
// remote.oauth2 provider is configured, or a human picks from a
// chooser page when there's more than one), and relies on the broker
// handing back that provider's own token_endpoint/client_id — public,
// non-secret OAuth2 client metadata, never anything Kayra would need
// to protect — at the very end, in the loopback callback itself, so
// the exchange below can still happen directly against the real
// provider and the actual access token is something only this CLI
// process ever sees. ctx bounds the whole wait for the browser round
// trip; status lines (including the URL to open, in case the browser
// couldn't be launched automatically) go to stderr.
func LoginToServer(ctx context.Context, serverBaseURL string, stderr io.Writer) (*Result, error) {
	if serverBaseURL == "" {
		return nil, fmt.Errorf("oauth2login: server is required")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("oauth2login: open local callback listener: %w", err)
	}
	localRedirectURL := fmt.Sprintf("http://%s%s", listener.Addr().String(), callbackPath)

	state, err := randomString(32)
	if err != nil {
		listener.Close()
		return nil, err
	}
	verifier := oauth2.GenerateVerifier()
	challenge := oauth2.S256ChallengeFromVerifier(verifier)

	resultCh := make(chan callbackResult, 1)
	errCh := make(chan error, 1)
	srv := &http.Server{Handler: callbackHandler(state, resultCh, errCh)}
	go func() { _ = srv.Serve(listener) }()
	defer srv.Close()

	base := strings.TrimRight(serverBaseURL, "/")
	authURL := base + "/oauth2/v1/authorize?" + url.Values{
		"redirect_uri":          {localRedirectURL},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	fmt.Fprintf(stderr, "oauth2login: opening browser to log in:\n\n  %s\n\n", authURL)
	if err := OpenBrowser(authURL); err != nil {
		fmt.Fprintf(stderr, "oauth2login: could not open a browser automatically (%v) — open the URL above by hand\n", err)
	}

	var result callbackResult
	select {
	case result = <-resultCh:
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, fmt.Errorf("oauth2login: timed out waiting for the browser login: %w", ctx.Err())
	}
	if result.TokenEndpoint == "" || result.ClientID == "" {
		return nil, fmt.Errorf("oauth2login: server did not relay a token endpoint/client id at the callback — is %s running a kayra build new enough for `kayra login`?", base)
	}

	// No local config, so no provider-specific proxy to honor either —
	// oidc.ClientFor("") still goes through the env-proxy-aware default
	// client, exactly what a plain end-user laptop needs.
	client, err := oidc.ClientFor("")
	if err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)

	cfg := &oauth2.Config{
		ClientID:    result.ClientID,
		Endpoint:    oauth2.Endpoint{TokenURL: result.TokenEndpoint},
		RedirectURL: base + "/oauth2/v1/callback",
	}
	token, err := cfg.Exchange(ctx, result.Code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("oauth2login: exchange code for token: %w", err)
	}

	return &Result{AccessToken: token.AccessToken, TokenType: token.TokenType, Expiry: token.Expiry}, nil
}

// callbackResult is what the loopback listener below hands back once
// the broker's relayed redirect lands on it: the authorization code,
// plus the public token_endpoint/client_id the broker resolved
// alongside it — everything LoginToServer needs to finish the PKCE
// exchange itself, having started with none of it.
type callbackResult struct {
	Code          string
	TokenEndpoint string
	ClientID      string
}

// callbackHandler answers the provider's (broker-relayed) redirect: a
// matching state and a code sends the full callbackResult on
// resultCh; a provider-reported error (or a state mismatch) sends an
// error on errCh instead. Either way, the browser gets a short
// human-readable page — there is nothing left for it to do once this
// fires.
func callbackHandler(wantState string, resultCh chan<- callbackResult, errCh chan<- error) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		if errParam := q.Get("error"); errParam != "" {
			writeCallbackPage(w, false)
			errCh <- fmt.Errorf("oauth2login: provider denied login: %s: %s", errParam, q.Get("error_description"))
			return
		}
		if q.Get("state") != wantState {
			writeCallbackPage(w, false)
			errCh <- fmt.Errorf("oauth2login: callback state mismatch (possible CSRF)")
			return
		}
		code := q.Get("code")
		if code == "" {
			writeCallbackPage(w, false)
			errCh <- fmt.Errorf("oauth2login: callback carried no code")
			return
		}
		writeCallbackPage(w, true)
		resultCh <- callbackResult{Code: code, TokenEndpoint: q.Get("token_endpoint"), ClientID: q.Get("client_id")}
	})
	return mux
}

func writeCallbackPage(w http.ResponseWriter, ok bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if ok {
		fmt.Fprint(w, "<html><body><p>Login complete — you can close this tab.</p></body></html>")
		return
	}
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprint(w, "<html><body><p>Login failed — check the terminal and try again.</p></body></html>")
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth2login: generate random state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// defaultOpenBrowser best-effort launches the OS's default browser —
// LoginToServer never depends on this succeeding (stderr always also
// prints the URL), since many CLI sessions (SSH, containers) have no
// browser to open at all.
func defaultOpenBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		cmd, args = "open", []string{url}
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		cmd, args = "xdg-open", []string{url}
	}
	return exec.Command(cmd, args...).Start()
}
