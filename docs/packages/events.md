---
title: events
description: "events.<domain>: the APIs' events stored in etcd under a TTL, their routes, who may report and read them, the rate per reporter."
weight: 35
---

# events

```go
import "github.com/infrapi/kayra/internal/events"
```

Serves `events.<domain>`. See [Events](../architecture/events.md) for the
model, the routes and the configuration.

```go
events.SetAPIDomain(apiDomain) // events.<domain>
events.Register(engine, authenticator.Middleware(), events.Options{
	Store: s, Keys: keys, Settings: settings, Stdout: os.Stdout,
	Namespace:  catalogRepo.CheckNamespace,                        // 404 for a namespace that does not exist
	Authorize:  func(ac, namespace, verb) (bool, string, error){…}, // the namespace's RBAC, the cluster's for ""
	Subscribed: func(namespace, api) *liberrors.Error {…},          // an API reports in its subscribed namespaces
})
```

- **`Event`** is the stored event; `validate` refuses a missing type, reason,
  regarding or controller, a reason that is no PascalCase word, and one too
  big.
- **Reporting:** an API's identity (`identity.ParseAPI`) reports about its own
  group's objects in a namespace `Subscribed` accepts; anyone else as
  `Authorize` grants `create`.
- **Storage:** `store.PutBatchTTL`, a batch in one etcd transaction under a
  lease shared for `store.LeaseReuse` (a minute); `store.Range` reads the
  keys newest first, a page at a time, the filters applied in Kayra.
- **Rate:** a token bucket per reporter; a `429` with `Retry-After`.
- **`PUT` and `DELETE`:** `405`.
