package oauth2server

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/infrapi/kayra/internal/config"
	kidentity "github.com/infrapi/kayra/internal/identity"
	"github.com/infrapi/kayra/internal/oidc"
)

// JWTBearer is the client assertion type of RFC 7523: the client
// authenticates with a JWT.
const JWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" //#nosec G101 -- a URN naming an assertion type, no credential

// maxAssertionLife is how long a client's own assertion (private_key_jwt)
// may live: a short one, used once.
const maxAssertionLife = 5 * time.Minute

// signingMethods are the algorithms an assertion may be signed with.
var signingMethods = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// MachineClient is one of Kayra's own identities as a client of the token
// endpoint: what authenticates it.
type MachineClient struct {
	// UID and Kind go into its token, as the token action's.
	UID, Kind string
	// Keys verify its own assertions (private_key_jwt).
	Keys []oidc.JWK
	// Federated trust a platform's tokens as it.
	Federated []kidentity.FederatedCredential
}

// ErrNoClient is what a MachineClients answers for a client id that is
// none of Kayra's own identities.
var ErrNoClient = errors.New("oauth2server: no such client")

// clientCredentials is the client_credentials grant (RFC 6749 4.4), for
// Kayra's own identities only: the client is authenticated by a JWT
// (RFC 7523), its own (iss is the client: signed by one of its keys) or a
// platform's (iss a trusted issuer: matching one of its federated
// credentials), and gets a token of its own, no refresh token.
func (s *Server) clientCredentials(c *gin.Context) {
	clientID := c.PostForm("client_id")
	if s.Clients == nil {
		tokenError(c, http.StatusBadRequest, "unsupported_grant_type", "client_credentials is not served here")
		return
	}
	if c.PostForm("client_assertion_type") != JWTBearer || c.PostForm("client_assertion") == "" {
		tokenError(c, http.StatusUnauthorized, "invalid_client", "authenticate with client_assertion_type "+JWTBearer+" and a client_assertion")
		return
	}
	client, err := s.Clients(clientID)
	if errors.Is(err, ErrNoClient) {
		tokenError(c, http.StatusUnauthorized, "invalid_client", fmt.Sprintf("%q is no client of client_credentials: a service account's subject, system:serviceaccount:<namespace>:<name>, or an API's registered with an identity, system:api:<group>", clientID))
		return
	}
	if err != nil {
		tokenError(c, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	resources := c.PostFormArray("resource")
	if len(resources) == 0 {
		resources = s.cfg.Resources[:1]
	}
	for _, r := range resources {
		if !s.allowedResource(r) {
			tokenError(c, http.StatusBadRequest, "invalid_target", fmt.Sprintf("resource %q is none of the resources tokens are issued for", r))
			return
		}
	}

	assertion := c.PostForm("client_assertion")
	unverified := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(assertion, unverified); err != nil {
		tokenError(c, http.StatusUnauthorized, "invalid_client", "client_assertion: "+err.Error())
		return
	}
	iss, _ := unverified.GetIssuer()
	if iss == clientID {
		err = s.ownAssertion(assertion, clientID, client)
	} else {
		err = s.federatedAssertion(assertion, iss, client)
	}
	if err != nil {
		tokenError(c, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	token, exp, err := s.IssueMachineToken(clientID, client.UID, client.Kind, slices.Clone(resources), s.ttl.ClientCredentials)
	if err != nil {
		tokenError(c, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"access_token": token, "token_type": "Bearer", "expires_in": int(time.Until(exp).Seconds())})
}

// ownAssertion checks a client's own assertion, private_key_jwt: signed by
// one of its keys, iss and sub the client, aud the token endpoint (or the
// issuer), living 5 minutes at most, its jti used once.
func (s *Server) ownAssertion(assertion, clientID string, client MachineClient) error {
	if len(client.Keys) == 0 {
		return fmt.Errorf("client_assertion: %s has no keys (jwks): sign with none of its own, or use a federated credential", clientID)
	}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(assertion, claims, keyOf(client.Keys), jwt.WithValidMethods(signingMethods),
		jwt.WithExpirationRequired(), jwt.WithLeeway(30*time.Second))
	if err != nil {
		return fmt.Errorf("client_assertion: %w", err)
	}
	if sub, _ := claims.GetSubject(); sub != clientID {
		return fmt.Errorf("client_assertion: sub %q is not the client", sub)
	}
	aud, _ := claims.GetAudience()
	if !slices.Contains(aud, s.issuer+"/oauth2/token") && !slices.Contains(aud, s.issuer) {
		return fmt.Errorf("client_assertion: aud %v holds neither %s/oauth2/token nor %s", aud, s.issuer, s.issuer)
	}
	exp, _ := claims.GetExpirationTime()
	if exp.Sub(s.now()) > maxAssertionLife {
		return fmt.Errorf("client_assertion: it lives until %s, more than %s from now", exp.Time.UTC().Format(time.RFC3339), maxAssertionLife)
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return fmt.Errorf("client_assertion: no jti")
	}
	// used once: kept until it expires
	var seen struct{}
	used, err := s.get("assertions", hash(clientID+"\x00"+jti), &seen)
	if err != nil {
		return err
	}
	if used {
		return fmt.Errorf("client_assertion: jti %q was used already", jti)
	}
	return s.put("assertions", hash(clientID+"\x00"+jti), struct{}{}, time.Until(exp.Time)+time.Minute)
}

// federatedAssertion checks a platform's token: from a trusted issuer,
// signed by one of its keys, unexpired, matching one of the client's
// federated credentials of that issuer (its audience, Kayra's URL by
// default, in aud). It may be presented again until it expires: a
// platform hands a job one token, not one per request.
func (s *Server) federatedAssertion(assertion, iss string, client MachineClient) error {
	trusted, ok := s.cfgAll.Federation.Issuer(iss)
	if !ok {
		return fmt.Errorf("client_assertion: issuer %q is not one Kayra trusts (federation.issuers), nor the client itself", iss)
	}
	var creds []kidentity.FederatedCredential
	for _, f := range client.Federated {
		if f.Issuer == iss {
			creds = append(creds, f)
		}
	}
	if len(creds) == 0 {
		return fmt.Errorf("client_assertion: the client has no federated credential of %s", iss)
	}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(assertion, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		keys, err := s.federation.keys(trusted, s.cfgAll.Federation.Proxy, kid)
		if err != nil {
			return nil, err
		}
		return keyOf(keys)(t)
	}, jwt.WithValidMethods(signingMethods), jwt.WithExpirationRequired(), jwt.WithIssuer(iss), jwt.WithLeeway(30*time.Second))
	if err != nil {
		return fmt.Errorf("client_assertion: %w", err)
	}
	aud, _ := claims.GetAudience()
	for _, f := range creds {
		want := f.Audience
		if want == "" {
			want = s.issuer
		}
		if slices.Contains(aud, want) && f.Matches(claims) {
			return nil
		}
	}
	sub, _ := claims.GetSubject()
	return fmt.Errorf("client_assertion: none of the client's federated credentials of %s matches sub %q, aud %v", iss, sub, aud)
}

// keyOf picks the key of a token's kid among keys, or tries them all when
// it names none.
func keyOf(keys []oidc.JWK) jwt.Keyfunc {
	return func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		var set jwt.VerificationKeySet
		for _, k := range keys {
			if kid != "" && k.Kid != kid {
				continue
			}
			pub, err := k.Key()
			if err != nil {
				continue
			}
			set.Keys = append(set.Keys, pub)
		}
		if len(set.Keys) == 0 {
			return nil, fmt.Errorf("no key %q", kid)
		}
		return set, nil
	}
}

// issuerKeys caches the trusted issuers' keys: fetched at first use, again
// after 10 minutes, or for a kid it does not hold, at most every 30
// seconds.
type issuerKeys struct {
	mu    sync.Mutex
	cache map[string]cachedKeys
	now   func() time.Time
}

type cachedKeys struct {
	keys    []oidc.JWK
	fetched time.Time
}

func (k *issuerKeys) keys(issuer config.FederationIssuer, proxy, kid string) ([]oidc.JWK, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	c, ok := k.cache[issuer.Issuer]
	fresh := ok && now.Sub(c.fetched) < 10*time.Minute
	held := slices.ContainsFunc(c.keys, func(j oidc.JWK) bool { return kid == "" || j.Kid == kid })
	if fresh && (held || now.Sub(c.fetched) < 30*time.Second) {
		return c.keys, nil
	}
	url := issuer.JWKSURL
	if url == "" {
		doc, err := oidc.FetchDiscovery(strings.TrimRight(issuer.Issuer, "/")+"/.well-known/openid-configuration", proxy)
		if err != nil {
			return nil, err
		}
		url = doc.JWKSURI
	}
	keys, err := oidc.FetchJWKS(url, proxy)
	if err != nil {
		if ok {
			return c.keys, nil // the last ones, while the issuer is unreachable
		}
		return nil, err
	}
	if k.cache == nil {
		k.cache = map[string]cachedKeys{}
	}
	k.cache[issuer.Issuer] = cachedKeys{keys: keys, fetched: now}
	return keys, nil
}
