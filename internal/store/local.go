package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// localWatchPollInterval is how often LocalStore.Watch rechecks a prefix
// for changes. LocalStore is just files on disk with no push primitive of
// its own (unlike etcd's native MVCC watch), so polling-and-diffing is the
// only option — acceptable for the "dev: local:" backend this simulates
// etcd for, not meant to carry production event traffic.
const localWatchPollInterval = 200 * time.Millisecond

// localEntry is the on-disk envelope for one key: the raw value plus an
// optional absolute expiry, so TTL semantics survive a process restart.
type localEntry struct {
	Value     []byte `json:"value"`
	ExpiresAt int64  `json:"expires_at"` // unix nano, 0 = no expiry
}

// LocalStore simulates etcd with a directory of files on disk. It is the
// "dev: local: path:" backend the spec calls out for testing without a real
// etcd cluster.
type LocalStore struct {
	root string
	mu   sync.Mutex
}

// NewLocalStore returns a LocalStore rooted at root, creating it if absent.
func NewLocalStore(root string) (*LocalStore, error) {
	if root == "" {
		return nil, fmt.Errorf("local store: root path is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("local store: create root %s: %w", root, err)
	}
	return &LocalStore{root: root}, nil
}

// keyPath maps an etcd-style key to a file path under root. Keys are
// expected to start with "/"; a leading-slash-stripped, cleaned path is
// joined onto root so "../" escapes are not possible.
func (s *LocalStore) keyPath(key string) string {
	clean := filepath.Clean("/" + key)
	return filepath.Join(s.root, clean)
}

func (s *LocalStore) Put(key string, value []byte) error {
	return s.PutTTL(key, value, 0)
}

func (s *LocalStore) PutTTL(key string, value []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := localEntry{Value: value}
	if ttl > 0 {
		entry.ExpiresAt = time.Now().Add(ttl).UnixNano()
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("local store: marshal %s: %w", key, err)
	}

	path := s.keyPath(key)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("local store: mkdir for %s: %w", key, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("local store: write %s: %w", key, err)
	}
	return nil
}

func (s *LocalStore) Get(key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.readEntry(s.keyPath(key))
}

// readEntry reads and decodes the entry at path, deleting and reporting
// ErrNotFound if it has expired. Caller must hold s.mu.
func (s *LocalStore) readEntry(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("local store: read %s: %w", path, err)
	}

	var entry localEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("local store: decode %s: %w", path, err)
	}

	if entry.ExpiresAt != 0 && time.Now().UnixNano() > entry.ExpiresAt {
		_ = os.Remove(path)
		return nil, ErrNotFound
	}

	return entry.Value, nil
}

func (s *LocalStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.Remove(s.keyPath(key)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("local store: delete %s: %w", key, err)
	}
	return nil
}

func (s *LocalStore) DeletePrefix(prefix string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var deleted int64

	err := filepath.WalkDir(s.root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(s.root, path)
		if err != nil {
			return err
		}
		key := "/" + filepath.ToSlash(rel)
		if !strings.HasPrefix(key, prefix) {
			return nil
		}

		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		deleted++
		return nil
	})
	if err != nil {
		return deleted, fmt.Errorf("local store: delete prefix %s: %w", prefix, err)
	}

	return deleted, nil
}

func (s *LocalStore) List(prefix string) (map[string][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make(map[string][]byte)

	err := filepath.WalkDir(s.root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(s.root, path)
		if err != nil {
			return err
		}
		key := "/" + filepath.ToSlash(rel)
		if !strings.HasPrefix(key, prefix) {
			return nil
		}

		value, err := s.readEntry(path)
		if err != nil {
			if err == ErrNotFound {
				return nil
			}
			return err
		}
		result[key] = value
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("local store: list %s: %w", prefix, err)
	}

	return result, nil
}

// Watch polls prefix every localWatchPollInterval and diffs the result
// against its previous snapshot, emitting an EventTypePut for each new or
// changed key and an EventTypeDelete for each key that disappeared.
func (s *LocalStore) Watch(ctx context.Context, prefix string) (<-chan Event, error) {
	prev, err := s.List(prefix)
	if err != nil {
		return nil, err
	}

	out := make(chan Event)
	go func() {
		defer close(out)

		ticker := time.NewTicker(localWatchPollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cur, err := s.List(prefix)
				if err != nil {
					continue
				}

				for key, value := range cur {
					if old, ok := prev[key]; !ok || !bytes.Equal(old, value) {
						if !sendEvent(ctx, out, Event{Type: EventTypePut, Key: key, Value: value}) {
							return
						}
					}
				}
				for key := range prev {
					if _, ok := cur[key]; !ok {
						if !sendEvent(ctx, out, Event{Type: EventTypeDelete, Key: key}) {
							return
						}
					}
				}
				prev = cur
			}
		}
	}()

	return out, nil
}

func (s *LocalStore) Close() error {
	return nil
}
