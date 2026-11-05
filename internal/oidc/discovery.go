package oidc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// DiscoveryDoc is the subset of an OIDC discovery document Kayra needs.
type DiscoveryDoc struct {
	Issuer                string `json:"issuer"`
	JWKSURI               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

// defaultHTTPClient is used whenever a provider sets no explicit proxy —
// its Transport is nil, so http.Client falls back to http.DefaultTransport,
// which already honors HTTP_PROXY/HTTPS_PROXY/NO_PROXY; discovery and JWKS
// documents are small and infrequent, so one conservative timeout suffices.
var defaultHTTPClient = &http.Client{Timeout: 10 * time.Second}

// ClientFor returns the *http.Client every outbound call for one provider
// should use: the shared, env-proxy-aware default when proxy is empty, or a
// client pinned to that exact proxy otherwise — each provider's outbound
// traffic (discovery, JWKS, userinfo, and oauth2login's own authorize/token
// calls) is routed independently, never through one process-wide setting.
func ClientFor(proxy string) (*http.Client, error) {
	if proxy == "" {
		return defaultHTTPClient, nil
	}
	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return nil, fmt.Errorf("oidc: parse proxy %q: %w", proxy, err)
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}, nil
}

// FetchDiscovery retrieves and parses the discovery document at url (a
// provider's /.well-known/openid-configuration), via proxy if set.
func FetchDiscovery(url, proxy string) (*DiscoveryDoc, error) {
	client, err := ClientFor(proxy)
	if err != nil {
		return nil, err
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("oidc: fetch discovery %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: discovery %s returned %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("oidc: read discovery %s: %w", url, err)
	}

	var doc DiscoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("oidc: parse discovery %s: %w", url, err)
	}
	if doc.JWKSURI == "" {
		return nil, fmt.Errorf("oidc: discovery %s has no jwks_uri", url)
	}
	return &doc, nil
}

// FetchJWKS retrieves the JWK set at url (a provider's jwks_uri), via proxy
// if set.
func FetchJWKS(url, proxy string) ([]JWK, error) {
	client, err := ClientFor(proxy)
	if err != nil {
		return nil, err
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("oidc: fetch jwks %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: jwks %s returned %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("oidc: read jwks %s: %w", url, err)
	}

	var set JWKSet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("oidc: parse jwks %s: %w", url, err)
	}
	return set.Keys, nil
}

// FetchUserinfo calls a provider's userinfo_endpoint with token and returns
// the decoded JSON response, via proxy if set.
func FetchUserinfo(url, token, proxy string) (map[string]any, error) {
	client, err := ClientFor(proxy)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: build userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: call userinfo %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: userinfo %s returned %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("oidc: read userinfo %s: %w", url, err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("oidc: parse userinfo %s: %w", url, err)
	}
	return result, nil
}
