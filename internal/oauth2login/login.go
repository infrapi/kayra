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
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
// authorizations.<name> entry). ApiDomain is this server's own
// resolved app.api_domain, relayed through the broker (see
// oauth2broker.pending.ApiDomain) so a caller (cmd/cli's `login`) can
// save it alongside the token instead of ever having to guess it.
type Result struct {
	AccessToken string
	TokenType   string
	Expiry      time.Time
	ApiDomain   string
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

	state, verifier, authURL, err := startLogin(serverBaseURL, localRedirectURL)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}

	resultCh := make(chan callbackResult, 1)
	errCh := make(chan error, 1)
	srv := &http.Server{Handler: callbackHandler(state, resultCh, errCh), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(listener) }()
	defer func() { _ = srv.Close() }()

	_, _ = fmt.Fprintf(stderr, "oauth2login: opening browser to log in:\n\n  %s\n\n", authURL)
	if err := OpenBrowser(authURL); err != nil {
		_, _ = fmt.Fprintf(stderr, "oauth2login: could not open a browser automatically (%v) — open the URL above by hand\n", err)
	}

	var result callbackResult
	select {
	case result = <-resultCh:
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, fmt.Errorf("oauth2login: timed out waiting for the browser login: %w", ctx.Err())
	}
	return exchange(ctx, serverBaseURL, result, verifier)
}

// OOBRedirectURI is the redirect_uri LoginToServerManual sends instead
// of a loopback address — the standard OAuth2 "out-of-band" value. It
// never reaches the provider (which always sees Kayra's own callback,
// exactly as for a loopback login): it only tells the broker to show
// the user a LoginCode to copy (see oauth2broker.handleCallback)
// instead of redirecting their browser to a local listener that, on
// another machine, wouldn't exist.
const OOBRedirectURI = "urn:ietf:wg:oauth:2.0:oob"

// LoginCode is everything a loopback callback would have carried,
// bundled into the one string the broker shows a no-browser login's
// user to paste back into their terminal (see EncodeLoginCode /
// DecodeLoginCode). Safe to display: Code is only redeemable together
// with the code_verifier, which never leaves the CLI process that
// started the login (PKCE), and State ties it to that one login.
type LoginCode struct {
	Code          string `json:"code"`
	State         string `json:"state"`
	TokenEndpoint string `json:"token_endpoint"`
	ClientID      string `json:"client_id"`
	ApiDomain     string `json:"api_domain"`
}

// EncodeLoginCode renders c as a single copy-pasteable token
// (base64url JSON, no padding — no characters a terminal or a
// copy/paste could mangle).
func EncodeLoginCode(c LoginCode) (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("oauth2login: encode login code: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// DecodeLoginCode is EncodeLoginCode's inverse; surrounding whitespace
// (a trailing newline, a stray space from copying) is ignored.
func DecodeLoginCode(s string) (LoginCode, error) {
	var c LoginCode
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return c, fmt.Errorf("oauth2login: login code is not valid — paste it exactly as shown in the browser: %w", err)
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("oauth2login: login code is not valid — paste it exactly as shown in the browser: %w", err)
	}
	return c, nil
}

// LoginToServerManual is LoginToServer for a terminal with no usable
// browser (SSH, a container, an air-gapped host): it starts no local
// listener and opens nothing. It prints the login URL to stderr for
// the user to open on any machine that has a browser; once they've
// logged in, the broker shows them a LoginCode, which they paste back
// at the prompt this reads from stdin. The final code→token exchange
// is identical to LoginToServer's — still directly against the
// provider, still with this process's own PKCE verifier — so this host
// must be able to reach the provider's token endpoint. ctx bounds the
// whole wait, including the prompt.
func LoginToServerManual(ctx context.Context, serverBaseURL string, stdin io.Reader, stderr io.Writer) (*Result, error) {
	if serverBaseURL == "" {
		return nil, fmt.Errorf("oauth2login: server is required")
	}

	state, verifier, authURL, err := startLogin(serverBaseURL, OOBRedirectURI)
	if err != nil {
		return nil, err
	}

	_, _ = fmt.Fprintf(stderr, "oauth2login: open this URL in a browser on any machine to log in:\n\n  %s\n\n", authURL)
	_, _ = fmt.Fprint(stderr, "Paste the login code shown in the browser: ")

	lineCh := make(chan string, 1)
	readErrCh := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && strings.TrimSpace(line) == "" {
			readErrCh <- fmt.Errorf("oauth2login: read login code: %w", err)
			return
		}
		lineCh <- line
	}()

	var line string
	select {
	case line = <-lineCh:
	case err := <-readErrCh:
		return nil, err
	case <-ctx.Done():
		return nil, fmt.Errorf("oauth2login: timed out waiting for the login code: %w", ctx.Err())
	}

	code, err := DecodeLoginCode(line)
	if err != nil {
		return nil, err
	}
	if code.State != state {
		return nil, fmt.Errorf("oauth2login: login code belongs to a different login attempt — paste the code from the URL this command printed")
	}
	if code.Code == "" {
		return nil, fmt.Errorf("oauth2login: login code carries no authorization code")
	}
	return exchange(ctx, serverBaseURL, callbackResult{
		Code:          code.Code,
		TokenEndpoint: code.TokenEndpoint,
		ClientID:      code.ClientID,
		ApiDomain:     code.ApiDomain,
	}, verifier)
}

// startLogin generates one login attempt's state and PKCE pair and
// builds the broker's /oauth2/v1/authorize URL for redirectURI (a
// loopback callback, or OOBRedirectURI).
func startLogin(serverBaseURL, redirectURI string) (state, verifier, authURL string, err error) {
	state, err = randomString(32)
	if err != nil {
		return "", "", "", err
	}
	verifier = oauth2.GenerateVerifier()
	authURL = strings.TrimRight(serverBaseURL, "/") + "/oauth2/v1/authorize?" + url.Values{
		"redirect_uri":          {redirectURI},
		"state":                 {state},
		"code_challenge":        {oauth2.S256ChallengeFromVerifier(verifier)},
		"code_challenge_method": {"S256"},
	}.Encode()
	return state, verifier, authURL, nil
}

// exchange finishes either login flavor: redeems result.Code at the
// provider's token endpoint the broker relayed, with this process's
// own PKCE verifier.
func exchange(ctx context.Context, serverBaseURL string, result callbackResult, verifier string) (*Result, error) {
	base := strings.TrimRight(serverBaseURL, "/")
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

	return &Result{AccessToken: token.AccessToken, TokenType: token.TokenType, Expiry: token.Expiry, ApiDomain: result.ApiDomain}, nil
}

// callbackResult is what the loopback listener below hands back once
// the broker's relayed redirect lands on it: the authorization code,
// plus the public token_endpoint/client_id the broker resolved
// alongside it — everything LoginToServer needs to finish the PKCE
// exchange itself, having started with none of it — and the server's
// own api_domain, carried along for Result but otherwise unused here.
type callbackResult struct {
	Code          string
	TokenEndpoint string
	ClientID      string
	ApiDomain     string
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
		resultCh <- callbackResult{Code: code, TokenEndpoint: q.Get("token_endpoint"), ClientID: q.Get("client_id"), ApiDomain: q.Get("api_domain")}
	})
	return mux
}

func writeCallbackPage(w http.ResponseWriter, ok bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if ok {
		_, _ = fmt.Fprint(w, "<html><body><p>Login complete — you can close this tab.</p></body></html>")
		return
	}
	w.WriteHeader(http.StatusBadRequest)
	_, _ = fmt.Fprint(w, "<html><body><p>Login failed — check the terminal and try again.</p></body></html>")
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
	// cmd is always one of the three hardcoded literals above, picked by
	// runtime.GOOS alone — never attacker-influenced — and url is passed
	// as a single argv entry, never through a shell, so there is nothing
	// here for shell metacharacters to reach.
	return exec.Command(cmd, args...).Start() //#nosec G204
}
