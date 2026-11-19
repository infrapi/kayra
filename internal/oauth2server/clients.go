package oauth2server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/config"
)

// client is a client, as the authorization server knows it.
type client struct {
	ID           string   `json:"client_id"`
	Name         string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	FirstParty   bool     `json:"first_party,omitempty"`
}

// docTTL is how long a metadata document is kept, at most.
const docTTL = time.Hour

type cachedDoc struct {
	client client
	until  time.Time
}

// client is the client id names: declared, a metadata document of a
// trusted host, or registered.
func (s *Server) client(id string) (client, error) {
	for _, c := range s.cfg.Clients {
		if c.ID == id {
			return client{ID: c.ID, Name: cmpOr(c.Name, c.ID), RedirectURIs: c.RedirectURIs, FirstParty: c.FirstParty}, nil
		}
	}
	if strings.HasPrefix(id, "https://") {
		return s.metadataDocument(id)
	}
	var c client
	ok, err := s.get("clients", id, &c)
	if err != nil {
		return client{}, err
	}
	if !ok {
		return client{}, fmt.Errorf("no client %q", id)
	}
	return c, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// metadataDocument is a Client ID Metadata Document: fetched from its
// client_id, an https URL with a path on a trusted host, cached; its
// client_id must be that URL, its client_name and redirect_uris set.
func (s *Server) metadataDocument(id string) (client, error) {
	u, err := url.Parse(id)
	if err != nil || u.Scheme != "https" || u.Path == "" || u.Path == "/" || u.Fragment != "" || u.User != nil {
		return client{}, fmt.Errorf("client_id %q: a metadata document's is an https URL with a path", id)
	}
	if !hostAllowed(u.Hostname(), s.cfg.MetadataDocumentHosts) {
		return client{}, fmt.Errorf("client_id %q: host %s is not trusted (oauth2.metadata_document_hosts)", id, u.Hostname())
	}
	s.docsLock.Lock()
	cached, ok := s.docs[id]
	s.docsLock.Unlock()
	if ok && s.now().Before(cached.until) {
		return cached.client, nil
	}
	resp, err := s.HTTPClient.Get(id)
	if err != nil {
		return client{}, fmt.Errorf("client_id %q: fetch its metadata document: %w", id, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return client{}, fmt.Errorf("client_id %q: its metadata document answered %d", id, resp.StatusCode)
	}
	var doc struct {
		ClientID                string   `json:"client_id"`
		ClientName              string   `json:"client_name"`
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&doc); err != nil {
		return client{}, fmt.Errorf("client_id %q: its metadata document: %w", id, err)
	}
	switch {
	case doc.ClientID != id:
		return client{}, fmt.Errorf("client_id %q: its metadata document names client_id %q", id, doc.ClientID)
	case doc.ClientName == "" || len(doc.RedirectURIs) == 0:
		return client{}, fmt.Errorf("client_id %q: its metadata document has no client_name or redirect_uris", id)
	case doc.TokenEndpointAuthMethod != "" && doc.TokenEndpointAuthMethod != "none":
		return client{}, fmt.Errorf("client_id %q: token_endpoint_auth_method %q: only public clients, none", id, doc.TokenEndpointAuthMethod)
	}
	for _, r := range doc.RedirectURIs {
		if err := config.CheckRedirectURI(r); err != nil {
			return client{}, fmt.Errorf("client_id %q: %w", id, err)
		}
	}
	c := client{ID: id, Name: doc.ClientName, RedirectURIs: doc.RedirectURIs}
	s.docsLock.Lock()
	s.docs[id] = cachedDoc{client: c, until: s.now().Add(docTTL)}
	s.docsLock.Unlock()
	return c, nil
}

// hostAllowed tells whether host is one of hosts, or under a *.domain of
// them.
func hostAllowed(host string, hosts []string) bool {
	host = strings.ToLower(host)
	return slices.ContainsFunc(hosts, func(h string) bool {
		h = strings.ToLower(h)
		if rest, ok := strings.CutPrefix(h, "*."); ok {
			return strings.HasSuffix(host, "."+rest)
		}
		return host == h
	})
}

// matchRedirect tells whether uri is one of c's: exactly, but a loopback
// one's port, any (RFC 8252 section 7.3).
func (c client) matchRedirect(uri string) bool {
	if slices.Contains(c.RedirectURIs, uri) {
		return true
	}
	got, err := url.Parse(uri)
	if err != nil || got.Scheme != "http" || !config.IsLoopback(got.Hostname()) {
		return false
	}
	return slices.ContainsFunc(c.RedirectURIs, func(r string) bool {
		want, err := url.Parse(r)
		return err == nil && want.Scheme == "http" && want.Hostname() == got.Hostname() &&
			want.Path == got.Path && want.RawQuery == got.RawQuery
	})
}

// register is RFC 7591: a public client, its redirect URIs loopback or on
// the trusted hosts.
func (s *Server) register(c *gin.Context) {
	var req struct {
		RedirectURIs            []string `json:"redirect_uris"`
		ClientName              string   `json:"client_name"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	if err := json.NewDecoder(io.LimitReader(c.Request.Body, 64<<10)).Decode(&req); err != nil {
		registerError(c, "invalid_client_metadata", "the body: "+err.Error())
		return
	}
	if req.TokenEndpointAuthMethod != "" && req.TokenEndpointAuthMethod != "none" {
		registerError(c, "invalid_client_metadata", "only public clients: token_endpoint_auth_method none")
		return
	}
	if len(req.RedirectURIs) == 0 {
		registerError(c, "invalid_redirect_uri", "redirect_uris is required")
		return
	}
	for _, r := range req.RedirectURIs {
		if err := config.CheckRedirectURI(r); err != nil {
			registerError(c, "invalid_redirect_uri", err.Error())
			return
		}
		u, _ := url.Parse(r)
		if !config.IsLoopback(u.Hostname()) && !hostAllowed(u.Hostname(), s.cfg.DynamicRegistration.Hosts) {
			registerError(c, "invalid_redirect_uri", fmt.Sprintf("redirect_uri %q: host %s may not register (oauth2.dynamic_registration.hosts)", r, u.Hostname()))
			return
		}
	}
	cl := client{ID: "dyn-" + random(16), Name: cmpOr(strings.TrimSpace(req.ClientName), "unnamed client"), RedirectURIs: req.RedirectURIs}
	if err := s.put("clients", cl.ID, cl, 0); err != nil {
		registerError(c, "server_error", err.Error())
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"client_id": cl.ID, "client_id_issued_at": s.now().Unix(), "client_name": cl.Name, "redirect_uris": cl.RedirectURIs,
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"},
		"token_endpoint_auth_method": "none",
	})
}

func registerError(c *gin.Context, code, desc string) {
	c.JSON(http.StatusBadRequest, gin.H{"error": code, "error_description": desc})
}

// redirectHost is what the consent page shows of a redirect URI: its host.
func redirectHost(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	if h, _, err := net.SplitHostPort(u.Host); err == nil {
		return h
	}
	return u.Host
}
