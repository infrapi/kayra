package config

import (
	"fmt"
	"net/url"
	"slices"
)

// FederationConfig is the federation: block: the identity providers of
// the platforms whose tokens a service account may be trusted as (its
// federated_credentials), a CI's say. Only the admin lists them: a
// namespace's admin picks among them, never adds one.
type FederationConfig struct {
	// Issuers are the trusted issuers.
	Issuers []FederationIssuer `yaml:"issuers"`
	// Proxy reaches them, as a remote provider's proxy: none when empty.
	Proxy string `yaml:"proxy"`
}

// FederationIssuer is one trusted issuer: its tokens' iss, and where its
// keys are when its OIDC discovery (<issuer>/.well-known/openid-configuration)
// is not reachable from Kayra.
type FederationIssuer struct {
	Issuer  string `yaml:"issuer"`
	JWKSURL string `yaml:"jwks_url"`
}

// Issuer is the trusted issuer iss, if it is one.
func (f FederationConfig) Issuer(iss string) (FederationIssuer, bool) {
	i := slices.IndexFunc(f.Issuers, func(i FederationIssuer) bool { return i.Issuer == iss })
	if i < 0 {
		return FederationIssuer{}, false
	}
	return f.Issuers[i], true
}

// validate refuses an issuer that is no https URL (http on a loopback
// address, for tests and the dev stack), listed twice, or a jwks_url or
// proxy that is no URL.
func (f FederationConfig) validate() error {
	seen := map[string]bool{}
	for _, i := range f.Issuers {
		if err := federationURL(i.Issuer); err != nil {
			return fmt.Errorf("federation.issuers: %q: %w", i.Issuer, err)
		}
		if seen[i.Issuer] {
			return fmt.Errorf("federation.issuers: %q listed twice", i.Issuer)
		}
		seen[i.Issuer] = true
		if i.JWKSURL != "" {
			if err := federationURL(i.JWKSURL); err != nil {
				return fmt.Errorf("federation.issuers.%s.jwks_url: %w", i.Issuer, err)
			}
		}
	}
	if f.Proxy != "" {
		if u, err := url.Parse(f.Proxy); err != nil || u.Host == "" {
			return fmt.Errorf("federation.proxy %q: a URL", f.Proxy)
		}
	}
	return nil
}

func federationURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" || u.RawQuery != "" {
		return fmt.Errorf("an https URL, without query or fragment")
	}
	if u.Scheme == "https" || (u.Scheme == "http" && IsLoopback(u.Hostname())) {
		return nil
	}
	return fmt.Errorf("https, or http on a loopback address")
}
