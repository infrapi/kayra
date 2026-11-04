package store

import (
	"fmt"

	"github.com/infrapi/kayra/internal/config"
)

// New builds the Store described by backend and the Keys it should be
// addressed through, picking etcd or local depending on which is set.
// Validate() on the config guarantees exactly one of them is non-nil.
func New(backend config.DatabaseBackend) (Store, Keys, error) {
	switch {
	case backend.Etcd != nil:
		s, err := NewEtcdStore(backend.Etcd)
		if err != nil {
			return nil, Keys{}, err
		}
		return s, NewKeys(backend.Etcd.Prefix), nil
	case backend.Local != nil:
		s, err := NewLocalStore(backend.Local.Path)
		if err != nil {
			return nil, Keys{}, err
		}
		return s, NewKeys(backend.Local.Prefix), nil
	default:
		return nil, Keys{}, fmt.Errorf("store: database backend has neither etcd nor local configured")
	}
}
