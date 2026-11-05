package store

import (
	"context"
	"testing"
	"time"
)

func TestLocalStorePutGet(t *testing.T) {
	s, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.Put("/kayra/foo/bar", []byte("hello")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := s.Get("/kayra/foo/bar")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("Get = %q, want %q", got, "hello")
	}
}

func TestLocalStoreGetMissing(t *testing.T) {
	s, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	if _, err := s.Get("/does/not/exist"); err != ErrNotFound {
		t.Fatalf("Get = %v, want ErrNotFound", err)
	}
}

func TestLocalStoreTTLExpiry(t *testing.T) {
	s, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.PutTTL("/kayra/ttl", []byte("v"), 10*time.Millisecond); err != nil {
		t.Fatalf("PutTTL: %v", err)
	}

	if _, err := s.Get("/kayra/ttl"); err != nil {
		t.Fatalf("Get before expiry: %v", err)
	}

	time.Sleep(30 * time.Millisecond)

	if _, err := s.Get("/kayra/ttl"); err != ErrNotFound {
		t.Fatalf("Get after expiry = %v, want ErrNotFound", err)
	}
}

func TestLocalStoreDelete(t *testing.T) {
	s, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.Put("/kayra/x", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete("/kayra/x"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get("/kayra/x"); err != ErrNotFound {
		t.Fatalf("Get after delete = %v, want ErrNotFound", err)
	}
	// deleting an absent key is not an error.
	if err := s.Delete("/kayra/x"); err != nil {
		t.Fatalf("Delete absent key: %v", err)
	}
}

func TestLocalStoreList(t *testing.T) {
	s, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	entries := map[string]string{
		"/kayra/namespaces/ns1/groups/a/config": "a",
		"/kayra/namespaces/ns1/groups/b/config": "b",
		"/kayra/namespaces/ns2/groups/c/config": "c",
	}
	for k, v := range entries {
		if err := s.Put(k, []byte(v)); err != nil {
			t.Fatalf("Put %s: %v", k, err)
		}
	}

	got, err := s.List("/kayra/namespaces/ns1/groups/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List returned %d entries, want 2: %v", len(got), got)
	}
}

func TestLocalStoreDeletePrefix(t *testing.T) {
	s, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	keys := NewKeys("")
	for _, e := range []struct{ authz, user string }{
		{"idm", "jdoe"}, {"idm", "asmith"}, {"dev", "jdoe"},
	} {
		if err := s.Put(keys.UserCache(e.authz, e.user), []byte("v")); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}

	// delete just one user under one authz
	n, err := s.DeletePrefix(keys.UserCache("idm", "jdoe"))
	if err != nil {
		t.Fatalf("DeletePrefix (one user): %v", err)
	}
	if n != 1 {
		t.Fatalf("DeletePrefix (one user) = %d, want 1", n)
	}
	if _, err := s.Get(keys.UserCache("idm", "asmith")); err != nil {
		t.Fatalf("Get(idm/asmith) should be untouched: %v", err)
	}

	// delete the rest of idm's users
	n, err = s.DeletePrefix(keys.UserCacheAuthzPrefix("idm"))
	if err != nil {
		t.Fatalf("DeletePrefix (authz): %v", err)
	}
	if n != 1 {
		t.Fatalf("DeletePrefix (authz) = %d, want 1", n)
	}

	// dev/jdoe must still be there, then clear everything
	if _, err := s.Get(keys.UserCache("dev", "jdoe")); err != nil {
		t.Fatalf("Get(dev/jdoe) should be untouched: %v", err)
	}
	n, err = s.DeletePrefix(keys.UserCachePrefix())
	if err != nil {
		t.Fatalf("DeletePrefix (all): %v", err)
	}
	if n != 1 {
		t.Fatalf("DeletePrefix (all) = %d, want 1", n)
	}
}

func TestLocalStoreWatchPutAndDelete(t *testing.T) {
	s, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events, err := s.Watch(ctx, "/kayra/namespaces/")
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}

	if err := s.Put("/kayra/namespaces/ns1/config", []byte("v1")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	select {
	case ev := <-events:
		if ev.Type != EventTypePut || ev.Key != "/kayra/namespaces/ns1/config" || string(ev.Value) != "v1" {
			t.Fatalf("Watch event = %+v, want Put ns1/config=v1", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Put event")
	}

	if err := s.Delete("/kayra/namespaces/ns1/config"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	select {
	case ev := <-events:
		if ev.Type != EventTypeDelete || ev.Key != "/kayra/namespaces/ns1/config" {
			t.Fatalf("Watch event = %+v, want Delete ns1/config", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Delete event")
	}
}

func TestLocalStoreWatchStopsOnContextCancel(t *testing.T) {
	s, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer func() { _ = s.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	events, err := s.Watch(ctx, "/kayra/")
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	cancel()

	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("expected channel to close with no more events after cancel")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for channel close after cancel")
	}
}

func TestKeysBuilders(t *testing.T) {
	k := NewKeys("")
	if k.Prefix != "/kayra" {
		t.Fatalf("default prefix = %q, want /kayra", k.Prefix)
	}
	if got, want := k.ClusterGroupConfig("sysadmin"), "/kayra/cluster/groups/sysadmin/config"; got != want {
		t.Fatalf("ClusterGroupConfig = %q, want %q", got, want)
	}
	if got, want := k.UserCache("idm", "jdoe"), "/kayra/cache/users/idm/jdoe"; got != want {
		t.Fatalf("UserCache = %q, want %q", got, want)
	}
	if got, want := k.UserCacheAuthzPrefix("idm"), "/kayra/cache/users/idm/"; got != want {
		t.Fatalf("UserCacheAuthzPrefix = %q, want %q", got, want)
	}
	if got, want := k.UserCachePrefix(), "/kayra/cache/users/"; got != want {
		t.Fatalf("UserCachePrefix = %q, want %q", got, want)
	}
	if got, want := k.AuthCachePrefix(), "/kayra/cache/authentifications/"; got != want {
		t.Fatalf("AuthCachePrefix = %q, want %q", got, want)
	}
}
