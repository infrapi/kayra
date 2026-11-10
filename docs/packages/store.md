---
title: store
description: "Key/value backend abstraction: etcd in production or a directory of files for local dev."
weight: 130
---

# store

```go
import "github.com/infrapi/kayra/internal/store"
```

Abstracts the key/value backend every other package persists to: a real
etcd cluster in production, or a directory of files for the `dev: local:`
backend the spec calls out for testing without etcd. Everything in Kayra
— [rbac](rbac.md), the [catalog](../architecture/overview.md#catalog), the
PAT keypair and token records, the resolved-user and JWKS caches — goes
through this one
interface.

## Store

```go
type Store interface {
	Put(key string, value []byte) error
	PutTTL(key string, value []byte, ttl time.Duration) error
	Get(key string) ([]byte, error)
	Delete(key string) error
	DeletePrefix(prefix string) (int64, error)
	List(prefix string) (map[string][]byte, error)
	Watch(ctx context.Context, prefix string) (<-chan Event, error)
	Close() error
}
```

Keys are etcd-style slash-separated paths. `Get` returns `ErrNotFound` when
a key is absent or has expired; deleting an absent key is not an error.

```go
s, keys, err := store.New(dbBackend) // dbBackend: config.DatabaseBackend
```

`New` picks `EtcdStore` or `LocalStore` depending on which of
`backend.Etcd`/`backend.Local` is set — [`config.Config.ActiveDatabase`](config.md#database)
guarantees exactly one is.

## EtcdStore

The production backend: `clientv3`, with mTLS when `tls.verify` names a
client cert/key, TLS-only verification via `cacert` otherwise. Every
operation runs under a 10-second context timeout.

## LocalStore

Simulates etcd with a directory of files on disk: each key maps to a file
(a leading-slash-stripped, cleaned path joined onto the root, so `../`
can't escape it), storing the value plus an optional absolute expiry so TTL
survives a process restart.

## Watch

```go
events, err := s.Watch(ctx, keys.NamespacesPrefix())
for ev := range events {
	// ev.Type: EventTypePut or EventTypeDelete
	// ev.Key, ev.Value
}
```

Streams every change under `prefix` until `ctx` is canceled, then closes
the channel. `EtcdStore` backs this with etcd's own MVCC watch — a real
push, not polling. The underlying watch stream can end on its own at any
time for reasons that have nothing to do with the caller (compaction, a
leader election, any transient disconnect) — `Watch` reconnects
automatically when this happens, resuming from the last revision it
actually observed (or the compaction response's own revision, if that one
was itself compacted away) so nothing in between is missed; a caller
only ever sees the channel close because *it* canceled `ctx`, never
because etcd's stream happened to hiccup. `LocalStore` has no push
primitive of its own, so it polls the prefix every 200ms and diffs
against its previous snapshot; fine for dev, not meant to carry
production event traffic.

Like etcd's own watch, this only streams changes **from the moment `Watch`
is called onward** — it is not a snapshot of what already exists. A
consumer that needs both (see
[`catalog.Reconciler`](../architecture/subscriptions.md#reconciler)) lists the
prefix once before watching it.

## JobLocker

```go
type JobLocker interface {
	TryLock(ctx context.Context, key string) (ok bool, release func() error, err error)
}
```

An optional capability, not part of `Store` itself — a backend that can
enforce mutual exclusion on a named job shared across every *process*
pointed at it, not just within one. This is not a concurrency bound (each
caller's own process-local pool already handles that — see
[`catalog.Reconciler`'s concurrency](../architecture/subscriptions.md#concurrency)
— independently per process, so more processes means more total
throughput, not a shared ceiling); it solves the problem of every process
watching the same prefix seeing the identical event stream, and so
without it, every one of them redundantly doing the same job at once.

`EtcdStore` implements it: `TryLock` is a single non-blocking
`concurrency.Mutex.TryLock` attempt at `key` (etcd's `concurrency`
package, backed by one lease-renewed `concurrency.Session` per store).
Someone else already holding `key` is reported as `ok == false`, not an
error — `TryLock` itself never retries; that's left to the caller, if it
wants a wait-until-free lock out of this non-blocking primitive (see
[`catalog.Reconciler`'s per-job locking](../architecture/subscriptions.md#per-job-locking),
which retries it on an interval so a racing call blocks and gets its turn
rather than being dropped). `LocalStore` does not implement it: a single
dev process has nothing else to coordinate with.

A caller type-asserts for this and simply always runs the job when the
active `Store` doesn't offer it.

## Keys

```go
keys := store.NewKeys(prefix) // defaults to "/kayra"
```

`Keys` builds every key path from one configured prefix, so the etcd
layout lives in one place:

| Method | Path |
|--------|------|
| `AuthCache(provider)` | `{prefix}/cache/authentifications/{provider}` |
| `UserCache(authz, userID)` | `{prefix}/cache/users/{authz}/{userID}` |
| `ClusterGroupConfig(name)` | `{prefix}/cluster/groups/{name}/config` |
| `ClusterRoleConfig(name)` | `{prefix}/cluster/roles/{name}/config` |
| `ClusterRoleBindingConfig(name)` | `{prefix}/cluster/rolebindings/{name}/config` |
| `ClusterApiRegistrationConfig(platform, region, name)` | `{prefix}/cluster/apiregistrations/{platform}/{region}/{name}/config` |
| `NamespaceConfig(namespace)` | `{prefix}/namespaces/{namespace}/config` |
| `NamespaceGroupConfig(ns, name)` | `{prefix}/namespaces/{ns}/groups/{name}/config` |
| `NamespaceRoleConfig(ns, name)` | `{prefix}/namespaces/{ns}/roles/{name}/config` |
| `NamespaceRoleBindingConfig(ns, name)` | `{prefix}/namespaces/{ns}/rolebindings/{name}/config` |
| `NamespaceSubscriptionConfig(ns, api)` | `{prefix}/namespaces/{ns}/subscriptions/{api}/config` |
| `PatToken(hash)` | `{prefix}/tokens/pat/{hash}` |
| `PatKeypair()` | `{prefix}/keys/pat` |

Every `*Prefix` counterpart (`ClusterGroupPrefix`, `NamespacesPrefix`, ...)
lists everything under it — used for `List`/`Watch`/`DeletePrefix` scans.

## JSON helpers

```go
store.PutJSON(s, key, value)       // json.Marshal + Put
store.GetJSON(s, key, &dest)       // Get + json.Unmarshal
store.ListConfigValues(s, prefix)  // List, filtered to keys ending "/config", sorted
```

The one generic helper [`rbac`](rbac.md) and `internal/catalog` share for
their `"/config"`-suffixed records, so both packages' keys coexist
under the same namespace tree without colliding with each other's sibling
data (a group's `/members`, say).

## Timestamps

Every resource Kayra persists — [`rbac`](rbac.md)'s `Group`/`Role`/
`RoleBinding` and `internal/catalog`'s `ApiRegistration`/`Namespace`/
`Subscription` — embeds `store.Timestamps` and is written through
`PutObject`, never `PutJSON` directly:

```go
type Group struct {
	Name string `json:"name"`
	// ...
	store.Timestamps `yaml:",inline"` // created_at, updated_at
}

store.PutObject(s, key, &group) // stamps group in place, then PutJSON
```

Both fields are server-owned, RFC 3339, UTC, and appear at the top level
of the object's JSON (`"created_at"`, `"updated_at"`) in etcd and in every
API response:

- `updated_at` is set to now on **every** write — a create, an API
  update, or an internal one (`ActivateNamespace`,
  `ActivateSubscription`, `SetSubscriptionSyncID`, ...).
- `created_at` is carried over from the record already stored at the
  key, so a `PUT` body that omits it (or sends anything else) can never
  change it. It is set to now when there is no record yet, or when the
  stored one predates timestamps.

The read of the existing record and the write are not one transaction:
two concurrent creates of the same key each stamp their own
`created_at`, and the last write wins, just as for every other field.
Caches and secrets that aren't API resources (the authz decision cache,
OIDC JWKS cache, OAuth2 broker state, the PAT keypair and PAT records,
which carry their own `CreatedAt`) are not stamped.
