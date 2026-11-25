---
title: API registrations
description: ApiRegistration declares that an API group exists and who owns it; Kayra never implements the API itself.
weight: 30
---

# API registrations

An `ApiRegistration` declares that an API group exists, scoped to this
deployment's own platform+region — "vault.infrapi.io", "pki.infrapi.io", "compute.infrapi.io". Kayra
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
	Name, ShortName, Version     string
	Platform, Region             string
	Active, Upstream, Downstream bool
	Owner, Description           string
	DependsOn                    []ApiRegistrationRef
	SyncID, Mode                 string
}
```

## Managing one

Full CRUD at `/apis/catalog.infrapi.io/v1/apiregistrations`, decided on the
[cluster RBAC](auth/rbac-and-auth.md#who-decides): the sysadmin binding, or a
global binding granting `apiregistrations` on `catalog.infrapi.io`.

`identity` gives the app behind it an identity of its own,
`system:api:<name>`, to get tokens and act as the API: see
[API identity](auth/api-identity.md). `uid`, `platform`, `region` and
`canary_namespaces` are set by Kayra: the
[contract](../development.md#contracts) marks them `readOnly`, and a
request sending one is a `400`.

`allowed_namespaces` restricts who may subscribe to it, and use it: every
namespace when empty. A namespace left out is refused at subscription,
and at its next `/check` when it is taken out later (`403`, naming the
api's owner).

> [!TIP]
> The commands below use `infrapi-cli`: [install it](https://infrapi.github.io/cli/getting-started/#1-install).

**infrapi-cli**

```bash
infrapi-cli create apiregistrations -d '{
    "name": "compute.infrapi.io",
    "short_name": "compute",
    "active": true,
    "owner": "sre-a"
  }'
```

**curl**

```bash
curl -s -X POST http://localhost:8080/apis/catalog.infrapi.io/v1/apiregistrations \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "name": "compute.infrapi.io",
    "short_name": "compute",
    "active": true,
    "owner": "sre-a"
  }'
```

A registration's id is its **long name** — the full API group URN it is
reachable under (`compute.infrapi.io`), a lowercase DNS name of at
least two labels; a single-label `name` is refused (`400`). It's the
only name anything else ever refers to it by: a subscription's
`api`, a `/v1/check` request's `api`, a `Role` rule's `apis`, a
`depends_on` entry, every URL below. `short_name` is optional — a single
label (`compute`), unique within this platform/region (`409` otherwise)
— an alias for display and step templates (`{{ .Subscription.ShortName }}`)
only: it never addresses the registration.

`version` is the API version the app serves (`v1`, `v2beta1`), `v1` when
left out; anything not like `v1` or `v2beta1` is refused (`400`). The app's
routes are under `/apis/<name>/<version>/`, its own endpoints (health,
metrics, OpenAPI, docs) under `/apis/<name>/<version>/-/`, which is where the
[reconciler](#openapi-spec) reads its spec.

Every route addresses a registration by **name alone** —
`/apis/catalog.infrapi.io/v1/apiregistrations/compute.infrapi.io`, never
`.../:platform/:region/compute` — because this instance already knows
its own `INFRAPI_APP_PLATFORM`/`_REGION`. Create silently stamps them
onto the record regardless of what (if anything) the request body
sends; list, get, update and delete can only ever reach a registration
in that same scope.

**infrapi-cli**

```bash
infrapi-cli get apiregistrations compute.infrapi.io
infrapi-cli update apiregistrations compute.infrapi.io -d '{"name": "compute.infrapi.io", "owner": "sre-b"}'
infrapi-cli delete apiregistrations compute.infrapi.io
```

**curl**

```bash
curl -s http://localhost:8080/apis/catalog.infrapi.io/v1/apiregistrations/compute.infrapi.io \
  -H "Authorization: Bearer $TOKEN"
curl -s -X PUT http://localhost:8080/apis/catalog.infrapi.io/v1/apiregistrations/compute.infrapi.io \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "compute.infrapi.io", "owner": "sre-b"}'
curl -s -X DELETE http://localhost:8080/apis/catalog.infrapi.io/v1/apiregistrations/compute.infrapi.io \
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
{"name": "app", "depends_on": [{"platform": "sandbox", "region": "eu-west-1", "name": "compute.infrapi.io"}]}
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
/apis/catalog.infrapi.io/v1/apiregistrations` mints one automatically
when the request doesn't name one, same `hashicorp/go-uuid` generator
`PUT .../sync` uses. A request that does name an explicit `sync_id`
keeps it as given.

The shorthand:

**infrapi-cli**

```bash
infrapi-cli update apiregistrations/sync compute.infrapi.io
```

**curl**

```bash
curl -s -X PUT http://localhost:8080/apis/catalog.infrapi.io/v1/apiregistrations/compute.infrapi.io/sync \
  -H "Authorization: Bearer $TOKEN"
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
To try a new target against one namespace first:

**infrapi-cli**

```bash
infrapi-cli update apiregistrations/sync compute.infrapi.io -d '{"canary_namespaces": ["sre"]}'
```

**curl**

```bash
curl -s -X PUT http://localhost:8080/apis/catalog.infrapi.io/v1/apiregistrations/compute.infrapi.io/sync \
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

**infrapi-cli**

```bash
infrapi-cli update apiregistrations/sync compute.infrapi.io
```

**curl**

```bash
curl -s -X PUT http://localhost:8080/apis/catalog.infrapi.io/v1/apiregistrations/compute.infrapi.io/sync \
  -H "Authorization: Bearer $TOKEN"
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
table as an OpenAPI document under its group's root,
`/apis/<api>/<version>/-/openapi.json`, beside its health, metrics and docs.
`<version>` is the registration's `version`, `v1` unless set: a registration
`{"name": "compute.infrapi.io", "version": "v2beta1"}` is read at
`/apis/compute.infrapi.io/v2beta1/-/openapi.json`. Whenever a registration's
`sync_id` or `version` changes, `kayra reconciler` fetches it through the gateway
(`<reconciler.gateway_url>/apis/<api>/<version>/-/openapi.json`, see
[config](../packages/config.md#reconciler)) and stores it in etcd with the
`sync_id` and version it was fetched for and the resources derived from its
paths, the app's own `-/` endpoints left out. Only
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
curl -s http://localhost:8080/apis/catalog.infrapi.io/v1/apiregistrations/telemetry.infrapi.io/openapi.json \
  -H "Authorization: Bearer $TOKEN"
```

`GET /apis` lists every api group with its resources: Kayra's own, derived
from its live route table, then each registration's, from its stored spec.
A registration with no spec yet is listed with no resources. This is what
[`infrapi-cli apis`](https://infrapi.github.io/cli/commands/#apis) shows.

## Checking sync status

`GET /apis/catalog.infrapi.io/v1/apiregistrations/:name/status` reports
the registration's own current `sync_id` plus every **active**
subscription's own sync state against it, in one call — rather than
listing every namespace's [subscriptions](subscriptions.md) by hand and
comparing each one's `expected_sync_id` yourself. A subscription still
pending its initial activation is omitted: there's no sync state to
report for one yet.

**infrapi-cli**

```bash
infrapi-cli get apiregistrations/status compute.infrapi.io
```

**curl**

```bash
curl -s http://localhost:8080/apis/catalog.infrapi.io/v1/apiregistrations/compute.infrapi.io/status \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "name": "compute.infrapi.io",
  "sync_id": "f872573b-8ad8-9dd5-79f0-234fcb41517e",
  "subscriptions": [
    {"namespace": "sre", "state": "success", "current_sync_id": "f872573b-8ad8-9dd5-79f0-234fcb41517e", "synced": true},
    {"namespace": "apps", "state": "success", "current_sync_id": "old-build", "synced": false}
  ]
}
```
