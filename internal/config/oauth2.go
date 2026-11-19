package config

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// OAuth2ServerConfig is Kayra's authorization server (internal/oauth2server):
// clients such as infrapi-cli, or an MCP client, get tokens of Kayra's own
// (the signer's, a local provider), renewed and revoked here. A human logs
// in at a provider of theirs: an authentifications.<name> with remote.oauth2,
// chosen on a page when there are several (LoginProviders). A provider
// without remote.oauth2 is never offered: its tokens are only checked when
// presented to an API (a CI job's, say). Kayra never sees a password.
type OAuth2ServerConfig struct {
	// Enabled mounts it: /.well-known/oauth-authorization-server,
	// /oauth2/{authorize,callback,consent,token,revoke,register}.
	Enabled bool `yaml:"enabled"`
	// Signer is the local provider whose issuer key signs the tokens:
	// self when empty.
	Signer string `yaml:"signer"`
	// AccessTokenTTL is an access token's: 15m when empty.
	AccessTokenTTL string `yaml:"access_token_ttl"`
	// RefreshTokenTTL bounds a login's refresh tokens, renewed or not:
	// 720h (30 days) when empty.
	RefreshTokenTTL string `yaml:"refresh_token_ttl"`
	// RefreshTokenIdle is how long a refresh token lives unused: 168h (7
	// days) when empty.
	RefreshTokenIdle string `yaml:"refresh_token_idle"`
	// Resources are the resources (RFC 8707) a token may be for, the
	// apps' URLs: a resource must start with one of them. app.url, Kayra's
	// own, when empty. A token's aud is its resource.
	Resources []string `yaml:"resources"`
	// Clients are the clients declared: infrapi-cli, a script...
	Clients []OAuth2Client `yaml:"clients"`
	// MetadataDocumentHosts are the hosts whose Client ID Metadata
	// Documents are trusted: a client_id that is an https URL of one of
	// them is fetched, its redirect_uris honored (claude.ai, say). None:
	// CIMD off.
	MetadataDocumentHosts []string `yaml:"metadata_document_hosts"`
	// DynamicRegistration is RFC 7591's, deprecated by MCP: off unless
	// enabled, and only for redirect URIs on its hosts, or loopback.
	DynamicRegistration DynamicRegistrationConfig `yaml:"dynamic_registration"`
}

// OAuth2Client is a client declared.
type OAuth2Client struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
	// RedirectURIs are matched exactly, but a loopback one's port: any
	// port of http://127.0.0.1/callback (RFC 8252).
	RedirectURIs []string `yaml:"redirect_uris"`
	// FirstParty skips the consent page: a client of InfraPI's own.
	FirstParty bool `yaml:"first_party"`
}

// DynamicRegistrationConfig is /oauth2/register.
type DynamicRegistrationConfig struct {
	Enabled bool `yaml:"enabled"`
	// Hosts are the hosts a registered https redirect URI may be on.
	Hosts []string `yaml:"hosts"`
}

// OAuth2Durations are a server's TTLs, its settings' or their defaults.
type OAuth2Durations struct{ Access, Refresh, Idle time.Duration }

// Durations parses the TTLs.
func (o OAuth2ServerConfig) Durations() (OAuth2Durations, error) {
	var d OAuth2Durations
	for _, f := range []struct {
		name, raw, def string
		into           *time.Duration
	}{
		{"access_token_ttl", o.AccessTokenTTL, "15m", &d.Access},
		{"refresh_token_ttl", o.RefreshTokenTTL, "720h", &d.Refresh},
		{"refresh_token_idle", o.RefreshTokenIdle, "168h", &d.Idle},
	} {
		raw := f.raw
		if raw == "" {
			raw = f.def
		}
		v, err := time.ParseDuration(raw)
		if err != nil || v <= 0 {
			return d, fmt.Errorf("oauth2.%s %q: a duration", f.name, f.raw)
		}
		*f.into = v
	}
	return d, nil
}

// validate checks the oauth2: block against the providers.
func (o OAuth2ServerConfig) validate(c *Config) error {
	if !o.Enabled {
		return nil
	}
	if len(c.LoginProviders()) == 0 {
		return fmt.Errorf("oauth2: no authentifications.<name> has remote.oauth2: a human has nowhere to log in")
	}
	signer := o.Signer
	if signer == "" {
		signer = "self"
	}
	sp, ok := c.Authentifications[signer]
	if !ok || !slices.ContainsFunc(sp.Local, func(k LocalSigningKey) bool { return k.Enabled && k.Issuer }) {
		return fmt.Errorf("oauth2.signer: %q is no local provider with an enabled issuer key", signer)
	}
	if _, err := o.Durations(); err != nil {
		return err
	}
	for _, r := range o.Resources {
		if u, err := url.Parse(r); err != nil || u.Scheme != "https" && u.Scheme != "http" || u.Host == "" || u.Fragment != "" {
			return fmt.Errorf("oauth2.resources: %q is not an http(s) URL without a fragment", r)
		}
	}
	seen := map[string]bool{}
	for _, cl := range o.Clients {
		if cl.ID == "" || strings.Contains(cl.ID, "://") || seen[cl.ID] {
			return fmt.Errorf("oauth2.clients: %q: an id, unique, not a URL (a URL is a metadata document's)", cl.ID)
		}
		seen[cl.ID] = true
		if len(cl.RedirectURIs) == 0 {
			return fmt.Errorf("oauth2.clients.%s: redirect_uris is required", cl.ID)
		}
		for _, r := range cl.RedirectURIs {
			if err := CheckRedirectURI(r); err != nil {
				return fmt.Errorf("oauth2.clients.%s: %w", cl.ID, err)
			}
		}
	}
	return nil
}

// CheckRedirectURI refuses a redirect URI that is neither https nor a
// loopback http one, or has a fragment (OAuth 2.1, MCP).
func CheckRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.Host == "" {
		return fmt.Errorf("redirect_uri %q: an absolute URL without a fragment", raw)
	}
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && IsLoopback(u.Hostname()):
		return nil
	}
	return fmt.Errorf("redirect_uri %q: https, or http on a loopback address", raw)
}

// IsLoopback tells a loopback host: localhost, 127.0.0.1, ::1.
func IsLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// LoginProviders are the providers a human may log in with at the
// authorization server: every enabled remote one with oauth2, by name. A
// provider without oauth2 is not one.
func (c *Config) LoginProviders() []string {
	var out []string
	for name, p := range c.Authentifications {
		if p.Remote != nil && p.Remote.Enabled && p.Remote.OAuth2 != nil {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}
