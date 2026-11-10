---
title: API registrations
description: ApiRegistration declares that an API group exists and who owns it; Kayra never implements the API itself.
weight: 30
---

# API registrations

An `ApiRegistration` declares that an API group exists, scoped to this
deployment's own platform+region — "vault.example.com", "pki.example.com", "compute.example.com". Kayra
**never implements the API it names**: whatever team owns it runs its
own service (using `infrapi/lib`, like any other app, to ask Kayra's
own `/apis/authorization.<domain>/v1/check` for RBAC) and is notified
of changes through [`Reconciler`](subscriptions.md#reconciler) —
agnostic of however that team's own API gateway (APISIX, Envoy, Kong,
...) actually routes requests to it. Ported from the legacy Postgres
`stacks` table. Repository and route code lives in `internal/catalog`,
backed by [store](../packages/store.md).

```go
type ApiRegistration struct {
	Name, Platform, Region       string
	Active, Upstream, Downstream bool
	Owner, Description           string
	DependsOn                    []ApiRegistrationRef
	SyncID, Mode                 string
}
```

## Managing one

Full CRUD at `/apis/catalog.example.com/v1/apiregistrations`, gated by
[`SysadminGate`](rbac-and-auth.md#two-gates-two-trust-tiers) — same trust
tier as the cluster RBAC objects.

**kayra-cli**

```bash
kayra-cli create catalog apiregistrations -d '{
    "name": "compute.example.com",
    "short_name": "compute",
    "active": true,
    "owner": "sre-a"
  }'
```

**curl**

```bash
curl -s -X POST http://localhost:8080/apis/catalog.example.com/v1/apiregistrations \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "name": "compute.example.com",
    "short_name": "compute",
    "active": true,
    "owner": "sre-a"
  }'
```

A registration's id is its **long name** — the full API group URN it is
reachable under (`compute.example.com`), a lowercase DNS name of at
least two labels; a single-label `name` is refused (`400`). It's the
only name anything else ever refers to it by: a subscription's
`api`, a `/v1/check` request's `api`, a `Role` rule's `apis`, a
`depends_on` entry, every URL below. `short_name` is optional — a single
label (`compute`), unique within this platform/region (`409` otherwise)
— an alias for display and step templates (`{{ .Subscription.ShortName }}`)
only: it never addresses the registration.

Every route addresses a registration by **name alone** —
`/apis/catalog.example.com/v1/apiregistrations/compute.example.com`, never
`.../:platform/:region/compute` — because this instance already knows
its own `INFRAPI_APP_PLATFORM`/`_REGION`. Create silently stamps them
onto the record regardless of what (if anything) the request body
sends; list, get, update and delete can only ever reach a registration
in that same scope.

**kayra-cli**

```bash
kayra-cli get catalog apiregistrations compute.example.com
kayra-cli update catalog apiregistrations compute.example.com -d '{"name": "compute.example.com", "owner": "sre-b"}'
kayra-cli delete catalog apiregistrations compute.example.com
```

**curl**

```bash
curl -s http://localhost:8080/apis/catalog.example.com/v1/apiregistrations/compute.example.com \
  -H "Authorization: Bearer $TOKEN"
curl -s -X PUT http://localhost:8080/apis/catalog.example.com/v1/apiregistrations/compute.example.com \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "compute.example.com", "owner": "sre-b"}'
curl -s -X DELETE http://localhost:8080/apis/catalog.example.com/v1/apiregistrations/compute.example.com \
  -H "Authorization: Bearer $TOKEN"
```

## Dependencies

`DependsOn` replaces the legacy model's separate "dependencies" table: a
list of `{platform, region, name}` refs, each validated to exist on
create/update. Unlike the registration's own identity, a dependency
*may* cross platform/region — the legacy model allowed a dependency
graph spanning every platform/region a single Postgres database served,
and that part carries over unchanged.

```json
{"name": "app", "depends_on": [{"platform": "sandbox", "region": "eu-west-1", "name": "compute.example.com"}]}
```

Deleting a registration is refused (`409`) while another registration's
`DependsOn`, or any [subscription](subscriptions.md), still references
it.

## Triggering reconcile

`SyncID` and `Mode` exist to drive
[subscription reconciliation](subscriptions.md#ongoing-action) — they
have no effect on the registration itself. `Reconciler` never
reconciles a subscriber against a registration whose `SyncID` is empty
— there's nothing yet to catch up to — so `POST
/apis/catalog.example.com/v1/apiregistrations` mints one automatically
when the request doesn't name one, same `hashicorp/go-uuid` generator
`PUT .../sync` uses. A request that does name an explicit `sync_id`
keeps it as given.

The shorthand:

**kayra-cli**

```bash
kayra-cli update catalog apiregistrations compute.example.com/sync -d '{}'
```

**curl**

```bash
curl -s -X PUT http://localhost:8080/apis/catalog.example.com/v1/apiregistrations/compute.example.com/sync \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{}'
```

stamps a fresh [`hashicorp/go-uuid`](https://github.com/hashicorp/go-uuid)-generated
value onto `SyncID` — that's the entire trigger. An explicit value is still
settable through the normal `PUT .../apiregistrations/:name` instead, if
you'd rather tag a release id than a random one. `Mode` is read by
[`Reconciler`](subscriptions.md#reconciler) when it reconciles a
subscription against this registration — a free-form key into
`reconciler.mode` in `kayra.yaml` (`"trigger"` and `"api"` in the
examples there, but any name works, since it's just a map), not a fixed
set of choices.

### Canary rollout

By default, bumping `SyncID` reconciles every active subscriber at once.
To try a new target against one tenant first:

**kayra-cli**

```bash
kayra-cli update catalog apiregistrations compute.example.com/sync -d '{"canary_namespaces": ["sre"]}'
```

**curl**

```bash
curl -s -X PUT http://localhost:8080/apis/catalog.example.com/v1/apiregistrations/compute.example.com/sync \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"canary_namespaces": ["sre"]}'
```

mints a fresh `SyncID` same as the plain shorthand, but
[`Reconciler`](subscriptions.md#per-job-locking) only reconciles the named
namespaces — every other active subscriber is left exactly as it was,
visibly pending (`current_sync_id` still behind `expected_sync_id`) until
released. Each namespace named must already be subscribed to the
registration (`404` otherwise, catching a typo before it becomes
"nothing reconciled and I don't know why").

Once satisfied, release the same build to everyone else:

**kayra-cli**

```bash
kayra-cli update catalog apiregistrations compute.example.com/sync -d '{}'
```

**curl**

```bash
curl -s -X PUT http://localhost:8080/apis/catalog.example.com/v1/apiregistrations/compute.example.com/sync \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{}'
```

called again with **no** `canary_namespaces` while a rollout is pending —
this reuses the exact `SyncID` the canary already validated (it does
**not** mint another one) and clears the restriction, so every remaining
subscriber reconciles to that same build. Calling the plain shorthand with
no rollout pending behaves exactly as before canary existed at all: a
fresh `SyncID`, straight to everyone.

`CanaryNamespaces` is pipeline state for an in-progress rollout, not a
spec field: only this endpoint ever sets or clears it, so an unrelated
`PUT .../apiregistrations/:name` mid-rollout (changing `owner`, say)
can't silently finish or restart one.

## OpenAPI spec

Kayra knows nothing about the app behind a registration, so it learns what
the app serves from the app itself. Every `infrapi/lib` app serves its route
table as an OpenAPI document at `/-/openapi.json`. Whenever a registration's
`sync_id` changes, `kayra reconciler` fetches it through the gateway
(`<reconciler.gateway_url>/apis/<api>/-/openapi.json`, see
[config](../packages/config.md#reconciler)) and stores it in etcd with the
`sync_id` it was fetched for and the resources derived from its paths. Only
one fetch runs per registration and `sync_id`, however many subscriptions
the sync fans out to.

**The spec is mandatory.** A sync can't complete without it: if the fetch
fails (gateway unset or unreachable, a non-200 response, a document that
isn't OpenAPI, or one over 1 MiB), no subscription moves to the new
`sync_id`. Each one is marked `state: error` and keeps its previous
`current_sync_id`, so an active subscription keeps working. The fetch is
retried on the next change to the registration or the subscription.

Resources come from the `/apis/<api>/v1/[namespaces/{namespace}/]<resource>[/{name}[/<action>]]`
paths. A path under `namespaces/{namespace}/` is a namespaced resource, an
action is part of the resource name (`dashboards/refresh`), and verbs follow
the HTTP method: `GET` is `list` on a collection and `get` on an item, and
`POST`, `PUT`, `PATCH` and `DELETE` are `create`, `update`, `patch` and
`delete`.

Any authenticated caller can read the stored spec, exactly as the app served
it:

```bash
curl -s http://localhost:8080/apis/catalog.example.com/v1/apiregistrations/telemetry.giservices.io/openapi.json \
  -H "Authorization: Bearer $TOKEN"
```

`GET /apis` lists every api group with its resources: Kayra's own, derived
from its live route table, then each registration's, from its stored spec.
A registration with no spec yet is listed with no resources. This is what
[`kayra-cli apis`](../cli.md#apis) shows.

## Checking sync status

`GET /apis/catalog.example.com/v1/apiregistrations/:name/status` reports
the registration's own current `sync_id` plus every **active**
subscription's own sync state against it, in one call — rather than
listing every namespace's [subscriptions](subscriptions.md) by hand and
comparing each one's `expected_sync_id` yourself. A subscription still
pending its initial activation is omitted: there's no sync state to
report for one yet.

**kayra-cli**

```bash
kayra-cli get catalog apiregistrations compute.example.com/status
```

**curl**

```bash
curl -s http://localhost:8080/apis/catalog.example.com/v1/apiregistrations/compute.example.com/status \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "name": "compute.example.com",
  "sync_id": "f872573b-8ad8-9dd5-79f0-234fcb41517e",
  "subscriptions": [
    {"namespace": "sre", "state": "success", "current_sync_id": "f872573b-8ad8-9dd5-79f0-234fcb41517e", "synced": true},
    {"namespace": "apps", "state": "success", "current_sync_id": "old-build", "synced": false}
  ]
}
```
