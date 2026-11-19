package oidc

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/infrapi/kayra/internal/config"
	"github.com/infrapi/kayra/internal/crypto"
	"github.com/infrapi/kayra/internal/store"
)

// Manager owns the JWKS cache for every remote authentication provider, and
// the already-decoded signing keys for every local ("self"-style) provider.
type Manager struct {
	store store.Store
	keys  store.Keys
	cfg   *config.Config
	local map[string][]crypto.SigningKey
}

// NewManager loads every provider's local signing keys (if any) and returns
// a Manager ready to serve and refresh JWKS caches.
func NewManager(s store.Store, keys store.Keys, cfg *config.Config) (*Manager, error) {
	local := make(map[string][]crypto.SigningKey)
	for name, provider := range cfg.Authentifications {
		if len(provider.Local) == 0 {
			continue
		}
		signingKeys, err := crypto.LoadSigningKeys(provider.Local)
		if err != nil {
			return nil, fmt.Errorf("provider %s: %w", name, err)
		}
		local[name] = signingKeys
	}

	return &Manager{store: s, keys: keys, cfg: cfg, local: local}, nil
}

// LocalKeys returns provider's decoded local signing keys, if any.
func (m *Manager) LocalKeys(provider string) []crypto.SigningKey {
	return m.local[provider]
}

// cachedKeys reads provider's cached JWKS from the store.
func (m *Manager) cachedKeys(provider string) ([]JWK, error) {
	data, err := m.store.Get(m.keys.AuthCache(provider))
	if err != nil {
		return nil, err
	}
	var keys []JWK
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, fmt.Errorf("oidc: decode cached keys for %s: %w", provider, err)
	}
	return keys, nil
}

// RefreshRemote re-fetches provider's discovery document and JWKS, and
// replaces its cache entry.
func (m *Manager) RefreshRemote(provider string) ([]JWK, error) {
	p, ok := m.cfg.Authentifications[provider]
	if !ok || p.Remote == nil {
		return nil, fmt.Errorf("oidc: %s is not a remote provider", provider)
	}

	doc, err := FetchDiscovery(p.Remote.URL, p.Remote.Proxy)
	if err != nil {
		return nil, err
	}

	keys, err := FetchJWKS(doc.JWKSURI, p.Remote.Proxy)
	if err != nil {
		return nil, err
	}
	for i := range keys {
		keys[i].InfraPIAuthProvider = provider
	}

	data, err := json.Marshal(keys)
	if err != nil {
		return nil, fmt.Errorf("oidc: marshal keys for %s: %w", provider, err)
	}
	if err := m.store.Put(m.keys.AuthCache(provider), data); err != nil {
		return nil, fmt.Errorf("oidc: cache keys for %s: %w", provider, err)
	}

	return keys, nil
}

// KeysFor returns provider's current keys, fetching and caching them if
// this is the first call for that provider.
func (m *Manager) KeysFor(provider string) ([]JWK, error) {
	if localKeys, ok := m.local[provider]; ok {
		jwks := make([]JWK, 0, len(localKeys))
		for _, k := range localKeys {
			jwks = append(jwks, NewJWK(provider, k.Kid, k.Algorithm, k.Public))
		}
		return jwks, nil
	}

	keys, err := m.cachedKeys(provider)
	if err == nil {
		return keys, nil
	}
	if err != store.ErrNotFound {
		return nil, err
	}
	return m.RefreshRemote(provider)
}

// AllKeys returns every provider's current keys, aggregated for the
// /oauth2/discovery/keys endpoint. A provider whose keys can't be fetched is
// skipped rather than failing the whole response.
func (m *Manager) AllKeys() []JWK {
	var all []JWK
	for name, provider := range m.cfg.Authentifications {
		if provider.Remote != nil && !provider.Remote.Enabled {
			continue
		}
		keys, err := m.KeysFor(name)
		if err != nil {
			continue
		}
		all = append(all, keys...)
	}
	return all
}

// ProviderKey is a key, and the provider holding it.
type ProviderKey struct {
	Provider string
	Key      JWK
}

// FindKeys are every provider's key identified by kid, by provider name:
// two providers may hold the same key (two entries for one Okta org, say),
// their tokens then told apart by their claims (authn.Verify). Local
// (self-signed) providers' keys need no I/O; remote ones are read from
// their caches, and only when no cache holds kid are all remote caches
// refreshed once and read again — the spec's "absent from cache ->
// refresh, otherwise don't" rule.
func (m *Manager) FindKeys(kid string) ([]ProviderKey, error) {
	var out []ProviderKey
	for name, keys := range m.local {
		for _, k := range keys {
			if k.Kid == kid {
				out = append(out, ProviderKey{name, NewJWK(name, k.Kid, k.Algorithm, k.Public)})
			}
		}
	}
	collect := func(read func(string) ([]JWK, error)) {
		for name, p := range m.cfg.Authentifications {
			if p.Remote == nil || !p.Remote.Enabled {
				continue
			}
			if keys, err := read(name); err == nil {
				if k, ok := findKid(keys, kid); ok {
					out = append(out, ProviderKey{name, k})
				}
			}
		}
	}
	collect(m.cachedKeys)
	if len(out) == 0 {
		collect(m.RefreshRemote)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("oidc: no provider holds kid %q", kid)
	}
	slices.SortFunc(out, func(a, b ProviderKey) int { return strings.Compare(a.Provider, b.Provider) })
	return out, nil
}

func findKid(keys []JWK, kid string) (JWK, bool) {
	for _, k := range keys {
		if k.Kid == kid {
			return k, true
		}
	}
	return JWK{}, false
}

// Required is what a token of provider, signed by its key kid, must carry:
// each claim one of its values, or for a list (aud, say) one of its
// elements. A remote provider's are its claims setting; a local key's,
// aud among its audiences when it declares any. Nothing else is assumed:
// which claim tells a provider's tokens for InfraPI apart (aud, cid, azp,
// iss...) is the configuration's choice.
func (m *Manager) Required(provider, kid string) (map[string][]string, error) {
	if keys, ok := m.local[provider]; ok {
		for _, k := range keys {
			if k.Kid == kid {
				if len(k.Audiences) == 0 {
					return nil, nil
				}
				return map[string][]string{"aud": k.Audiences}, nil
			}
		}
		return nil, fmt.Errorf("oidc: provider %s has no key %q", provider, kid)
	}
	p, ok := m.cfg.Authentifications[provider]
	if !ok || p.Remote == nil {
		return nil, fmt.Errorf("oidc: unknown provider %q", provider)
	}
	out := make(map[string][]string, len(p.Remote.Claims))
	for k, v := range p.Remote.Claims {
		out[k] = v
	}
	return out, nil
}
