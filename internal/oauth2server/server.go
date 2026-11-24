// Package oauth2server is Kayra's authorization server (OAuth 2.1, the MCP
// authorization specification): clients such as infrapi-cli, or an MCP
// client, get tokens of Kayra's own, renewed and revoked here.
//
//	GET  /.well-known/oauth-authorization-server   RFC 8414 metadata
//	GET  /oauth2/authorize                          authorization code + PKCE S256, resource (RFC 8707)
//	GET  /oauth2/login                              the provider chosen, when there are several
//	GET  /oauth2/callback                           the provider's redirect
//	POST /oauth2/consent                            the human's consent
//	POST /oauth2/token                              authorization_code, refresh_token (rotated)
//	POST /oauth2/revoke                             RFC 7009
//	POST /oauth2/register                           RFC 7591, when enabled
//
// A human never logs in at Kayra: /oauth2/authorize sends them to the login
// provider (Okta, say), Kayra exchanges the code with a PKCE of its own and
// checks the provider's token exactly as any of its tokens is checked
// (middleware.Authenticator: its claims, its user, its groups). Then Kayra
// signs, with its signer's key: an access token (a JWT, short-lived, its aud
// the resource), and a refresh token (opaque, stored hashed, rotated at each
// use: a refresh token used twice revokes its whole family).
//
// A client is declared (oauth2.clients), or a Client ID Metadata Document of
// a trusted host (its client_id an https URL), or registered (RFC 7591).
package oauth2server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/config"
	gcrypto "github.com/infrapi/kayra/internal/crypto"
	"github.com/infrapi/kayra/internal/middleware"
	"github.com/infrapi/kayra/internal/store"
)

// CLIClient is infrapi-cli's client, built in: first-party, redirected to a
// loopback port (RFC 8252), or shown its code to paste (OOBRedirectURI) on
// a host with no browser. oauth2.clients may declare it otherwise.
const CLIClient = "infrapi-cli"

// OOBRedirectURI is infrapi-cli auth login --no-browser's redirect URI:
// Kayra shows the code, for the human to paste in their terminal, instead
// of redirecting. infrapi-cli's only: the code is redeemable with its PKCE
// verifier alone, which never leaves the CLI.
const OOBRedirectURI = "urn:ietf:wg:oauth:2.0:oob"

// TTLs of what is in flight.
const (
	loginTTL   = 10 * time.Minute // at the login provider
	consentTTL = 10 * time.Minute // on the consent page
	codeTTL    = time.Minute      // an authorization code
)

// Server is the authorization server.
type Server struct {
	cfg    config.OAuth2ServerConfig
	ttl    config.OAuth2Durations
	cfgAll *config.Config // the providers a human logs in with: those with remote.oauth2
	auth   *middleware.Authenticator
	store  store.Store
	prefix string // the store's
	issuer string // Kayra's public URL
	signer gcrypto.SigningKey
	// HTTPClient fetches the metadata documents: one with a timeout, no
	// redirects followed, when nil.
	HTTPClient *http.Client
	// Now is the clock: time.Now when nil.
	Now func() time.Time
	// CanManageSessions tells whether the cluster RBAC grants the caller
	// verb on another user's sessions: only their own when nil.
	CanManageSessions func(ac *middleware.AuthContext, verb string) bool
	// Clients finds one of Kayra's own identities by its client id, for
	// client_credentials (ErrNoClient for any other id): the grant is
	// refused when nil.
	Clients func(clientID string) (MachineClient, error)

	mu   sync.Mutex // refresh rotation, in this process
	docs map[string]cachedDoc
	// federation caches the trusted issuers' keys
	federation issuerKeys
	docsLock   sync.Mutex
}

// New is the server cfg describes, its issuer baseURL. auth checks the login
// provider's tokens; its Revoked is set to the server's.
func New(cfg *config.Config, auth *middleware.Authenticator, s store.Store, keys store.Keys, baseURL string) (*Server, error) {
	o := cfg.OAuth2
	ttl, err := o.Durations()
	if err != nil {
		return nil, err
	}
	signerName := o.Signer
	if signerName == "" {
		signerName = "self"
	}
	var signer gcrypto.SigningKey
	for _, k := range auth.Manager.LocalKeys(signerName) {
		if k.Private != nil {
			signer = k
			break
		}
	}
	if signer.Private == nil {
		return nil, fmt.Errorf("oauth2server: provider %s has no issuer key", signerName)
	}
	if len(o.Resources) == 0 {
		o.Resources = []string{strings.TrimRight(baseURL, "/")}
	}
	if !slices.ContainsFunc(o.Clients, func(c config.OAuth2Client) bool { return c.ID == CLIClient }) {
		o.Clients = append(o.Clients, config.OAuth2Client{
			ID: CLIClient, RedirectURIs: []string{"http://127.0.0.1/callback", OOBRedirectURI}, FirstParty: true,
		})
	}
	srv := &Server{
		cfg: o, ttl: ttl, cfgAll: cfg, auth: auth, store: s, prefix: keys.Prefix + "/oauth2",
		issuer: strings.TrimRight(baseURL, "/"), signer: signer, docs: map[string]cachedDoc{},
		HTTPClient: &http.Client{
			Timeout:       5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	srv.federation.now = srv.now
	auth.Revoked = srv.Revoked
	return srv, nil
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// RegisterRoutes mounts the server's routes on r, unauthenticated: they are
// the login.
func (s *Server) RegisterRoutes(r gin.IRouter) {
	r.GET("/.well-known/oauth-authorization-server", s.metadata)
	r.GET("/oauth2/authorize", s.authorize)
	r.GET("/oauth2/login", s.chosen)
	r.GET("/oauth2/callback", s.callback)
	r.POST("/oauth2/consent", s.consent)
	r.POST("/oauth2/token", s.token)
	r.POST("/oauth2/revoke", s.revoke)
	// a user's logins, the authenticator's caller's
	sessions := r.Group("/oauth2/sessions", s.auth.Middleware())
	sessions.GET("", s.listSessions)
	sessions.DELETE("", s.revokeSessions)
	sessions.DELETE("/:id", s.revokeSession)
	if s.cfg.DynamicRegistration.Enabled {
		r.POST("/oauth2/register", s.register)
	}
}

func (s *Server) metadata(c *gin.Context) {
	m := gin.H{
		"issuer":                                           s.issuer,
		"authorization_endpoint":                           s.issuer + "/oauth2/authorize",
		"token_endpoint":                                   s.issuer + "/oauth2/token",
		"revocation_endpoint":                              s.issuer + "/oauth2/revoke",
		"jwks_uri":                                         s.issuer + "/oauth2/discovery/keys",
		"response_types_supported":                         []string{"code"},
		"grant_types_supported":                            []string{"authorization_code", "refresh_token", "client_credentials"},
		"code_challenge_methods_supported":                 []string{"S256"},
		"token_endpoint_auth_methods_supported":            []string{"none", "private_key_jwt"},
		"token_endpoint_auth_signing_alg_values_supported": signingMethods,
		"revocation_endpoint_auth_methods_supported":       []string{"none"},
		"authorization_response_iss_parameter_supported":   true,
		"client_id_metadata_document_supported":            len(s.cfg.MetadataDocumentHosts) > 0,
	}
	if s.cfg.DynamicRegistration.Enabled {
		m["registration_endpoint"] = s.issuer + "/oauth2/register"
	}
	c.JSON(http.StatusOK, m)
}

// --- the store's records ---

// request is an authorization request, checked.
type request struct {
	Client      string `json:"client"`
	ClientName  string `json:"client_name"`
	FirstParty  bool   `json:"first_party"`
	RedirectURI string `json:"redirect_uri"`
	State       string `json:"state"`
	Challenge   string `json:"challenge"`
	Resource    string `json:"resource"`
	Scope       string `json:"scope"`
}

// identity is who logged in, as the authenticator resolved them.
type identity struct {
	UserID        string   `json:"user_id"`
	Provider      string   `json:"provider"`
	Authorization string   `json:"authorization"`
	Groups        []string `json:"groups"`
}

type pendingLogin struct {
	request
	Provider string `json:"provider"` // the authentifications.<name> logged in at
	Verifier string `json:"verifier"` // Kayra's own PKCE, at the provider
	Nonce    string `json:"nonce"`    // its ID token's
}

type pendingConsent struct {
	request
	identity
}

type authCode struct {
	request
	identity
}

// refreshToken is a refresh token's record, by its hash.
type refreshToken struct {
	Family   string    `json:"family"`
	Client   string    `json:"client"`
	Resource string    `json:"resource"`
	Scope    string    `json:"scope"`
	Used     bool      `json:"used"`
	Created  time.Time `json:"created"`
	identity
}

// family is a login's refresh tokens: revoked together.
type family struct {
	Client   string    `json:"client"`
	UserID   string    `json:"user_id"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"last_used"`
	Revoked  bool      `json:"revoked"`
}

func (s *Server) key(kind, id string) string { return s.prefix + "/" + kind + "/" + id }

func (s *Server) put(kind, id string, v any, ttl time.Duration) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.store.PutTTL(s.key(kind, id), data, ttl)
}

// get reads a record: false when absent or expired.
func (s *Server) get(kind, id string, v any) (bool, error) {
	data, err := s.store.Get(s.key(kind, id))
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(data, v)
}

// take reads and deletes a record: single use.
func (s *Server) take(kind, id string, v any) (bool, error) {
	ok, err := s.get(kind, id, v)
	if ok {
		err = errors.Join(err, s.store.Delete(s.key(kind, id)))
	}
	return ok, err
}

// Revoked tells whether an access token was revoked: its jti, or its
// session (sid), the login it is of.
func (s *Server) Revoked(claims map[string]any) (bool, error) {
	if jti, _ := claims["jti"].(string); jti != "" {
		var v struct{}
		if ok, err := s.get("revoked", jti, &v); ok || err != nil {
			return ok, err
		}
	}
	if sid, _ := claims["sid"].(string); sid != "" {
		var fam family
		ok, err := s.get("families", sid, &fam)
		return ok && fam.Revoked, err
	}
	return false, nil
}

// --- helpers ---

func random(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// hash is a secret's key in the store: never the secret itself.
func hash(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// challengeOf is PKCE S256's challenge of verifier.
func challengeOf(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// allowedResource tells whether resource is under one of the resources.
func (s *Server) allowedResource(resource string) bool {
	return slices.ContainsFunc(s.cfg.Resources, func(p string) bool {
		p = strings.TrimRight(p, "/")
		return resource == p || strings.HasPrefix(resource, p+"/")
	})
}
