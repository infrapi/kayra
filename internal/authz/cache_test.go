package authz

import (
	"testing"
	"time"

	"github.com/infrapi/kayra/internal/store"
)

type countingBackend struct {
	calls int
	info  UserInfo
}

func (b *countingBackend) ResolveUser(userID string) (UserInfo, error) {
	b.calls++
	return b.info, nil
}

func TestCachedResolveUserHitsBackendOnce(t *testing.T) {
	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer s.Close()

	backend := &countingBackend{info: UserInfo{ID: "jdoe", Attributes: map[string]string{"email": "jdoe@example.com"}}}
	cached := NewCached(backend, s, store.NewKeys(""), "idm")

	for i := 0; i < 3; i++ {
		info, err := cached.ResolveUser("jdoe", time.Minute)
		if err != nil {
			t.Fatalf("ResolveUser: %v", err)
		}
		if info.Attributes["email"] != "jdoe@example.com" {
			t.Fatalf("Attributes[email] = %q", info.Attributes["email"])
		}
	}

	if backend.calls != 1 {
		t.Fatalf("backend.calls = %d, want 1 (subsequent calls should hit the cache)", backend.calls)
	}
}

func TestCachedResolveUserExpires(t *testing.T) {
	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer s.Close()

	backend := &countingBackend{info: UserInfo{ID: "jdoe"}}
	cached := NewCached(backend, s, store.NewKeys(""), "idm")

	if _, err := cached.ResolveUser("jdoe", 10*time.Millisecond); err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	time.Sleep(30 * time.Millisecond)
	if _, err := cached.ResolveUser("jdoe", time.Minute); err != nil {
		t.Fatalf("ResolveUser after expiry: %v", err)
	}

	if backend.calls != 2 {
		t.Fatalf("backend.calls = %d, want 2 (cache entry should have expired)", backend.calls)
	}
}
