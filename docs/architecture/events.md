---
title: Events
description: "events.infrapi.io: what happened to the APIs' resources, reported by the APIs themselves, kept for a week, read with infrapi-cli get events, with series and spam limits as in Kubernetes."
weight: 27
---

# Events

Kayra serves `events.infrapi.io`: what happened to the APIs' resources, a VM
created, a reboot that failed. It works like Kubernetes' events:

- **The APIs report them**, each with its [own identity](auth/api-identity.md). An
  app built on infrapi/lib records one for every write it serves, and its
  workers record more ([lib's events package](https://infrapi.github.io/lib/packages/events/)).
- **Kayra keeps them in etcd for `events.ttl`**, a week by default, counted
  from the last time each was seen.
- **A namespace's readers read them** with `infrapi-cli get events`.

Events are best effort: one may be lost. Who asked for what, and whether it
was allowed, is the [audit](audit.md)'s job. The two share the request's
`request_id`.

The examples use [`infrapi-cli`](https://infrapi.github.io/cli/getting-started/#1-install)
against a Kayra at `https://kayra.example.com`, and the `compute` API
subscribed by the `core` namespace.

## 1. Read them

**infrapi-cli**

```bash
infrapi-cli get events -n core
# LAST SEEN  TYPE     REASON          OBJECT     COUNT  NOTE
# 34s        Warning  VMCreateFailed  vms/bad    30     no capacity for bad
# 2m         Normal   VMCreated       vms/web-1  1
infrapi-cli get events -n core --field-selector type=Warning,regarding.name=bad
```

**curl**

```bash
curl -s "https://kayra.example.com/apis/events.infrapi.io/v1/namespaces/core/events?type=Warning&regarding.name=bad" \
  -H "Authorization: Bearer $TOKEN"
```

- **Order:** the newest first, by the time Kayra received them.
- **Filters:** `type`, `reason`, `action`, `user`, `reporter`,
  `reporting_controller`, `regarding.api`, `regarding.resource` and
  `regarding.name`, each matched exactly.
- **`since` and `until`:** bound the reception, as an RFC 3339 time or a
  duration back from now: `since=1h`.
- **`limit`:** 100 by default, 1000 at most.
- **One event:** `GET .../events/<id>`.
- **Without `-n`:** the cluster's events, `/apis/events.infrapi.io/v1/events`,
  about objects in no namespace.

## 2. Who may read them

A role of the namespace grants `get` and `list` on `events.infrapi.io`, as
for any other API:

**infrapi-cli**

```bash
infrapi-cli create roles -n core -d '{"name": "events-read",
  "metadata": {"namespace": "core", "region": "eu-west-1", "platform": "sandbox"},
  "rules": [{"apis": ["events.infrapi.io"], "resources": ["events"], "verbs": ["get", "list"]}]}'
```

**curl**

```bash
curl -s -X POST https://kayra.example.com/apis/authorization.infrapi.io/v1/namespaces/core/roles \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "events-read", "metadata": {"namespace": "core", "region": "eu-west-1", "platform": "sandbox"},
       "rules": [{"apis": ["events.infrapi.io"], "resources": ["events"], "verbs": ["get", "list"]}]}'
```

**OpenTofu/Terraform**

```hcl
resource "kayra_role" "events_read" {
  namespace = "core"
  name      = "events-read"
  metadata = {
    namespace = "core"
    region    = "eu-west-1"
    platform  = "sandbox"
  }
  rules = [{
    apis      = ["events.infrapi.io"]
    resources = ["events"]
    verbs     = ["get", "list"]
  }]
}
```

Bind it to the namespace's groups (see [RBAC & auth](auth/rbac-and-auth.md#the-rbac-model)).
The cluster's events are read with the cluster RBAC.

## 3. Who may report them

- **An API, with its own identity** (`system:api:compute.infrapi.io`), needs
  no grant. It reports about its own objects only (`regarding.api` is its
  group), in the namespaces subscribed to it, and about its objects in no
  namespace. Anything else is a `403`.
- **Anyone else** (a user, a [service account](auth/service-accounts.md)) reports
  with `create` on `events.infrapi.io` granted by the namespace's roles.

## The event

```json
{"id": "01a20a18-b3c3-7ab8-…", "received_at": "2026-11-23T20:31:02Z", "reporter": "system:api:compute.infrapi.io",
 "regarding": {"api": "compute.infrapi.io", "namespace": "core", "resource": "vms", "name": "bad"},
 "type": "Warning", "reason": "VMCreateFailed", "note": "no capacity for bad", "action": "create",
 "reporting_controller": "compute", "user": "jdoe", "request_id": "req-1",
 "time": "2026-11-23T20:31:02Z", "series": {"count": 30, "last_observed": "2026-11-23T20:31:05Z"}}
```

- **Required:** `type` (`Normal` or `Warning`), `reason` (a PascalCase word),
  `regarding.api` and `regarding.resource`, and `reporting_controller`.
- **Set by Kayra:** `id` (a UUIDv7: the events sort by reception),
  `received_at` and `reporter`, the token's subject. `regarding.namespace` is
  the request's.
- **Limits:** a note of 1024 bytes, details of 4 KiB of JSON, 100 events in
  a batch.

## Reporting one

**curl**

```bash
curl -s -X POST https://kayra.example.com/apis/events.infrapi.io/v1/namespaces/core/events \
  -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: application/json" \
  -d '{"regarding": {"api": "compute.infrapi.io", "resource": "vms", "name": "web-1"},
       "type": "Normal", "reason": "VMRebooted", "reporting_controller": "compute-worker"}'
```

The body is one event, or `{"items": [...]}`, 100 at most. infrapi/lib's
recorder sends them in batches.

- **Series:** the same event seen again is not reported again. Its reporter
  sends `PATCH .../events/<id>` with `{"series": {"count": 30,
  "last_observed": "…"}}`, nothing else. Only its reporter may, and the count
  never decreases. Its `ttl` counts from then.
- **Never changed otherwise:** there is no `PUT` nor `DELETE` (a `404`). An event expires.
- **Rate:** each reporter may send `events.rate.per_second` events (50), and
  `burst` at once (200). Beyond that Kayra answers `429` with `Retry-After`,
  which the recorder waits out.

## Configure it

```yaml
events:
  ttl: 168h                 # kept this long after last seen, a minute at least
  stdout: false             # also a JSON line on Kayra's stdout per event
  rate: {per_second: 50, burst: 200}
```

- **Storage:** `<prefix>/events/namespaces/<ns>/<id>` and
  `<prefix>/events/cluster/<id>`, under etcd leases shared by the events
  written within a minute. An event may therefore live up to a minute longer
  than `ttl`.
- **Discovery:** `/.well-known/kayra.json` names the group (`apis.events`),
  and `GET /apis` lists its resource.
- **The audit:** an allowed event write is not audited, only a denied one.
- **Metrics:** `kayra_events_received_total{result}`: `accepted`, `invalid`,
  `denied` or `limited`.
