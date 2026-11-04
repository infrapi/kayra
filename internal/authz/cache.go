package authz

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/infrapi/kayra/internal/store"
)

// Cached wraps an Authorizer with the etcd user cache the spec describes:
// "cache user's info for 'exp' duration ... to avoid multiple ldap call
// during a session with multiple calls with a valid token." name is the
// authorizations.<name> this backend was built from, scoping the cache key
// so two providers sharing a user id never collide.
type Cached struct {
	backend Authorizer
	store   store.Store
	keys    store.Keys
	name    string
}

// NewCached returns a Cached wrapping backend under name.
func NewCached(backend Authorizer, s store.Store, keys store.Keys, name string) *Cached {
	return &Cached{backend: backend, store: s, keys: keys, name: name}
}

// ResolveUser returns userID's cached info if present and unexpired,
// otherwise resolves it through the backend and caches it for ttl.
func (c *Cached) ResolveUser(userID string, ttl time.Duration) (UserInfo, error) {
	key := c.keys.UserCache(c.name, userID)

	if data, err := c.store.Get(key); err == nil {
		var info UserInfo
		if err := json.Unmarshal(data, &info); err == nil {
			return info, nil
		}
	}

	info, err := c.backend.ResolveUser(userID)
	if err != nil {
		return UserInfo{}, err
	}

	data, err := json.Marshal(info)
	if err != nil {
		return UserInfo{}, fmt.Errorf("authz: marshal cached user %s: %w", userID, err)
	}
	if err := c.store.PutTTL(key, data, ttl); err != nil {
		return UserInfo{}, fmt.Errorf("authz: cache user %s: %w", userID, err)
	}

	return info, nil
}
