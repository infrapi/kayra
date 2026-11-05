package crypto

import (
	"testing"

	"github.com/infrapi/kayra/internal/config"
	"github.com/infrapi/kayra/internal/store"
)

func TestLoadOrCreatePatKeypairPersists(t *testing.T) {
	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer func() { _ = s.Close() }()
	keys := store.NewKeys("")

	priv1, err := LoadOrCreatePatKeypair(s, keys, config.PatConfig{})
	if err != nil {
		t.Fatalf("LoadOrCreatePatKeypair (first): %v", err)
	}

	priv2, err := LoadOrCreatePatKeypair(s, keys, config.PatConfig{})
	if err != nil {
		t.Fatalf("LoadOrCreatePatKeypair (second): %v", err)
	}

	if priv1.N.Cmp(priv2.N) != 0 {
		t.Fatalf("LoadOrCreatePatKeypair: second call generated a new key instead of reusing the persisted one")
	}
}
