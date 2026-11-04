// Package store abstracts the key/value backend Kayra persists everything
// to: a real etcd cluster in production, or a directory of files for the
// "dev: local:" backend the spec calls out for testing without etcd.
package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by Get when the key does not exist, or existed but
// has expired.
var ErrNotFound = errors.New("store: key not found")

// Store is the key/value contract every backend implements. Keys are
// etcd-style slash-separated paths; List returns every entry whose key has
// the given prefix.
type Store interface {
	// Put writes value at key with no expiry.
	Put(key string, value []byte) error

	// PutTTL writes value at key, expiring it after ttl. ttl <= 0 behaves
	// like Put.
	PutTTL(key string, value []byte, ttl time.Duration) error

	// Get reads the value at key. It returns ErrNotFound when the key is
	// absent or expired.
	Get(key string) ([]byte, error)

	// Delete removes key. Deleting an absent key is not an error.
	Delete(key string) error

	// DeletePrefix removes every key starting with prefix and reports how
	// many were deleted. Used to clear a whole cache subtree (e.g. every
	// cached user, or one provider's JWKS) rather than one key at a time.
	DeletePrefix(prefix string) (int64, error)

	// List returns every non-expired key/value pair whose key starts with
	// prefix.
	List(prefix string) (map[string][]byte, error)

	// Watch streams a Put/Delete Event for every change under prefix until
	// ctx is canceled, then closes the returned channel. EtcdStore backs
	// this with etcd's own MVCC watch; LocalStore (a directory of files,
	// with no push primitive of its own) polls and diffs instead — fine
	// for the "dev: local:" backend this simulates etcd for, not meant to
	// carry production event traffic.
	Watch(ctx context.Context, prefix string) (<-chan Event, error)

	// Close releases any resource the backend holds.
	Close() error
}

// JobLocker is an optional capability: a Store backend that can enforce
// mutual exclusion on a named job shared across every process pointed at
// it, not just within one process. EtcdStore implements it (etcd's own
// lease-backed distributed locks make cross-process coordination
// possible); LocalStore does not — a single dev process has no other
// process to coordinate with, so there is nothing distributed to offer.
//
// This is not a concurrency bound: it doesn't limit how many different
// jobs run at once (each caller's own process-local pool already does
// that — see catalog.Reconciler.dispatch — independently per process, so
// running more processes multiplies total throughput rather than sharing
// one fixed ceiling). It solves a different problem — every process
// watching the same etcd prefix sees the exact same stream of events (a
// broadcast, not a work queue), so without this, every process would
// redundantly run the exact same job (e.g. reconciling the same
// subscription) whenever a single event arrives. TryLock lets only one of
// them actually do it.
type JobLocker interface {
	// TryLock attempts to claim exclusive ownership of key, shared by
	// every caller against this same backend, and returns immediately —
	// it never blocks waiting for key to free up; that is the caller's
	// job, if it wants one (see catalog.Reconciler.withJobLock, which
	// retries this on an interval to turn it into a wait-until-free
	// lock, since two different callers racing for the same key should
	// both eventually run, serialized, rather than the loser being
	// silently dropped). ok is false (not an error) when some other
	// caller already holds it. The returned release func must be called
	// exactly once, and only when ok is true; failing to call it leaks
	// the lock until the backend's own session/lease expiry reclaims it.
	TryLock(ctx context.Context, key string) (ok bool, release func() error, err error)
}

// EventType is what happened to the key an Event reports on.
type EventType int

const (
	EventTypePut EventType = iota
	EventTypeDelete
)

// Event is one change a Watch observed: a key was written (EventTypePut,
// Value is the new value) or removed (EventTypeDelete, Value is empty).
type Event struct {
	Type  EventType
	Key   string
	Value []byte
}

// sendEvent delivers ev on out, reporting false without sending if ctx is
// already canceled — shared by every Watch implementation's goroutine so a
// caller that cancels ctx is never blocked on a channel nothing reads
// anymore.
func sendEvent(ctx context.Context, out chan<- Event, ev Event) bool {
	select {
	case out <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}
