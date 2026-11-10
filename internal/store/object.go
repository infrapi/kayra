package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Timestamps is embedded in every resource Kayra persists (rbac's
// Group/Role/RoleBinding, catalog's ApiRegistration/Namespace/
// Subscription). Both fields are server-owned: PutObject sets them on
// every write, so whatever a client sends for either is ignored.
// JSON flattens them into the resource's own object ("created_at",
// "updated_at", RFC 3339, UTC); YAML needs the embedding field tagged
// `yaml:",inline"` to do the same.
type Timestamps struct {
	CreatedAt time.Time `json:"created_at" yaml:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at,omitempty"`
}

func (t *Timestamps) stamps() *Timestamps { return t }

// Object is any record PutObject can stamp — i.e. any struct embedding
// Timestamps, passed by pointer.
type Object interface {
	stamps() *Timestamps
}

// Now is the clock PutObject stamps with. Tests may replace it.
var Now = func() time.Time { return time.Now().UTC() }

// PutObject writes obj at key like PutJSON, after stamping it: UpdatedAt
// is always set to Now, and CreatedAt is carried over from the record
// already stored at key — or set to Now too when there is none (a
// create), or when that record predates timestamps. obj is updated in
// place, so a caller can return it as-is. The read and the write are
// not one transaction: two concurrent creates of the same key can each
// stamp their own CreatedAt, last write wins — the same semantics every
// other field of a Put already has.
func PutObject(s Store, key string, obj Object) error {
	now := Now()
	ts := obj.stamps()

	var prev Timestamps
	data, err := s.Get(key)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &prev); err != nil {
			return fmt.Errorf("store: unmarshal existing %s: %w", key, err)
		}
	case errors.Is(err, ErrNotFound):
	default:
		return fmt.Errorf("store: read existing %s: %w", key, err)
	}

	ts.CreatedAt = prev.CreatedAt
	if ts.CreatedAt.IsZero() {
		ts.CreatedAt = now
	}
	ts.UpdatedAt = now
	return PutJSON(s, key, obj)
}
