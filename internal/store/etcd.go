package store

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"

	"github.com/infrapi/kayra/internal/config"
)

// EtcdStore is the production Store backend: a real etcd cluster, reached
// over plain https or mTLS per the database.<name>.etcd.tls config block.
type EtcdStore struct {
	client *clientv3.Client

	// session backs every TryLock call's concurrency.Mutex: one per
	// EtcdStore (not one per call), created lazily on first use and kept
	// for the store's lifetime. Its lease is kept alive automatically by
	// the etcd client for as long as this process is alive and connected
	// — if it crashes, the lease (and so every lock it held) expires on
	// its own, with no manual renewal logic needed here.
	sessionOnce sync.Once
	session     *concurrency.Session
	sessionErr  error
}

// NewEtcdStore dials cfg's endpoints and returns a ready Store.
func NewEtcdStore(cfg *config.EtcdConfig) (*EtcdStore, error) {
	if cfg == nil {
		return nil, fmt.Errorf("etcd store: config is required")
	}

	clientCfg := clientv3.Config{
		Endpoints:   cfg.Host,
		DialTimeout: time.Duration(cfg.Timeout) * time.Second,
	}

	tlsConfig, err := buildTLSConfig(cfg.TLS)
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil {
		clientCfg.TLS = tlsConfig
	}

	client, err := clientv3.New(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("etcd store: connect: %w", err)
	}

	return &EtcdStore{client: client}, nil
}

// buildTLSConfig turns the spec's tls: block (verify/cacert/key/cert) into a
// *tls.Config. mTLS (key+cert) is only honoured when verify is enabled, per
// the spec's "only support mtls if configured, and use cacert to verify etcd
// ssl cert if https".
func buildTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	if cfg == nil || !cfg.Verify {
		return nil, nil
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	if cfg.CACert != "" {
		caCert, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("etcd store: read cacert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("etcd store: cacert %s has no valid certificates", cfg.CACert)
		}
		tlsConfig.RootCAs = pool
	}

	if cfg.Cert != "" && cfg.Key != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("etcd store: load client keypair: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

func (s *EtcdStore) Put(key string, value []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := s.client.Put(ctx, key, string(value))
	if err != nil {
		return fmt.Errorf("etcd store: put %s: %w", key, err)
	}
	return nil
}

func (s *EtcdStore) PutTTL(key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		return s.Put(key, value)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	seconds := int64(ttl.Seconds())
	if seconds < 1 {
		seconds = 1
	}

	lease, err := s.client.Grant(ctx, seconds)
	if err != nil {
		return fmt.Errorf("etcd store: grant lease for %s: %w", key, err)
	}

	if _, err := s.client.Put(ctx, key, string(value), clientv3.WithLease(lease.ID)); err != nil {
		return fmt.Errorf("etcd store: put %s: %w", key, err)
	}
	return nil
}

func (s *EtcdStore) Get(key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := s.client.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("etcd store: get %s: %w", key, err)
	}
	if len(resp.Kvs) == 0 {
		return nil, ErrNotFound
	}
	return resp.Kvs[0].Value, nil
}

func (s *EtcdStore) Delete(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := s.client.Delete(ctx, key); err != nil {
		return fmt.Errorf("etcd store: delete %s: %w", key, err)
	}
	return nil
}

func (s *EtcdStore) DeletePrefix(prefix string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := s.client.Delete(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return 0, fmt.Errorf("etcd store: delete prefix %s: %w", prefix, err)
	}
	return resp.Deleted, nil
}

func (s *EtcdStore) List(prefix string) (map[string][]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := s.client.Get(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("etcd store: list %s: %w", prefix, err)
	}

	result := make(map[string][]byte, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		result[string(kv.Key)] = kv.Value
	}
	return result, nil
}

// watchReconnectInterval is how long Watch waits before re-establishing
// etcd's watch stream after it ends for any reason short of ctx being
// canceled. A var, not a const, so tests can shorten it.
var watchReconnectInterval = time.Second

// Watch backs Store.Watch with etcd's native MVCC watch: every Put/Delete
// under prefix, from the moment Watch is called, streams through the
// returned channel with no polling involved.
//
// etcd's own watch stream can end on its own at any time — most commonly
// compaction removing a revision the watch still needed, but also a
// leader election or any transient disconnect — without that being
// something the caller did (ctx is still live). The underlying
// clientv3.WatchChan simply closes when this happens; a caller that
// treats that the same as "ctx was canceled, stop for good" silently
// goes deaf on prefix forever; see catalog.Reconciler, whose entire model
// depends on this never happening quietly. So here, ending for any
// reason other than ctx itself being done re-establishes the watch
// instead of giving up — resuming from the last revision actually
// observed (or, if that revision was itself compacted away by the time
// of the error, from the compaction response's own CompactRevision) so
// no event in between is missed, after a short watchReconnectInterval
// backoff.
func (s *EtcdStore) Watch(ctx context.Context, prefix string) (<-chan Event, error) {
	out := make(chan Event)

	go func() {
		defer close(out)

		var lastRevision int64
		for {
			opts := []clientv3.OpOption{clientv3.WithPrefix()}
			if lastRevision > 0 {
				opts = append(opts, clientv3.WithRev(lastRevision+1))
			}

			for resp := range s.client.Watch(ctx, prefix, opts...) {
				if err := resp.Err(); err != nil {
					if resp.CompactRevision > 0 {
						lastRevision = resp.CompactRevision - 1
					}
					break
				}
				for _, ev := range resp.Events {
					e := Event{Key: string(ev.Kv.Key), Value: ev.Kv.Value}
					if ev.Type == clientv3.EventTypeDelete {
						e.Type = EventTypeDelete
						e.Value = nil
					}
					lastRevision = ev.Kv.ModRevision
					if !sendEvent(ctx, out, e) {
						return
					}
				}
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(watchReconnectInterval):
			}
		}
	}()

	return out, nil
}

// lockSession lazily creates (once) and returns this store's shared
// concurrency.Session, the lease every TryLock mutex is backed by.
func (s *EtcdStore) lockSession() (*concurrency.Session, error) {
	s.sessionOnce.Do(func() {
		s.session, s.sessionErr = concurrency.NewSession(s.client)
	})
	return s.session, s.sessionErr
}

// TryLock implements JobLocker: a single non-blocking attempt
// (concurrency.Mutex.TryLock) at key, shared by every other caller
// against this same etcd cluster (every mutex here rides this store's one
// session). Someone else already holding it is reported as ok=false, not
// an error — there is no retry loop here, since the caller's own
// re-dispatch (the next watch event, or reconcileExisting's next pass)
// is what retries.
func (s *EtcdStore) TryLock(ctx context.Context, key string) (bool, func() error, error) {
	session, err := s.lockSession()
	if err != nil {
		return false, nil, fmt.Errorf("etcd store: try lock: open session: %w", err)
	}

	mu := concurrency.NewMutex(session, key)
	switch err := mu.TryLock(ctx); {
	case err == nil:
		return true, func() error {
			unlockCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := mu.Unlock(unlockCtx); err != nil {
				return fmt.Errorf("etcd store: release lock %s: %w", mu.Key(), err)
			}
			return nil
		}, nil
	case errors.Is(err, concurrency.ErrLocked):
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("etcd store: try lock %s: %w", key, err)
	}
}

func (s *EtcdStore) Close() error {
	if s.session != nil {
		_ = s.session.Close()
	}
	return s.client.Close()
}
