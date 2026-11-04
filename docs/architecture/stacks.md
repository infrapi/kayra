# Stacks

A `Stack` is a cluster-wide infrastructure component definition — "vault",
"pki", "compute", scoped to this deployment's own platform+region. Ported
from the legacy Postgres `stacks` table. Repository and
route code lives in `internal/catalog`, backed by
[store](../packages/store.md).

```go
type Stack struct {
	Name, Platform, Region       string
	Active, Upstream, Downstream bool
	Owner, Description           string
	DependsOn                    []StackRef
	SyncID, Mode                 string
}
```

## Managing one

Full CRUD at `/apis/catalog.example.com/v1/stacks`, gated by
[`SysadminGate`](rbac-and-auth.md#two-gates-two-trust-tiers) — same trust
tier as the cluster RBAC objects.

```bash
curl -s -X POST http://localhost:8080/apis/catalog.example.com/v1/stacks \
  -H "Authorization: Bearer $TOKEN" -d '{
    "name": "compute",
    "active": true,
    "owner": "sre-a"
  }'
```

Every route addresses a stack by **name alone** —
`/apis/catalog.example.com/v1/stacks/compute`, never `.../:platform/:region/compute` —
because this instance already knows its own
`INFRAPI_APP_PLATFORM`/`_REGION`. Create silently stamps them onto the
record regardless of what (if anything) the request body sends; list, get,
update and delete can only ever reach a stack in that same scope.

```bash
curl -s http://localhost:8080/apis/catalog.example.com/v1/stacks/compute -H "Authorization: Bearer $TOKEN"
curl -s -X PUT http://localhost:8080/apis/catalog.example.com/v1/stacks/compute -H "Authorization: Bearer $TOKEN" -d '{"name": "compute", "owner": "sre-b"}'
curl -s -X DELETE http://localhost:8080/apis/catalog.example.com/v1/stacks/compute -H "Authorization: Bearer $TOKEN"
```

## Dependencies

`DependsOn` replaces the legacy model's separate "dependencies" table: a
list of `{platform, region, name}` refs, each validated to exist on
create/update. Unlike the stack's own identity, a dependency *may* cross
platform/region — the legacy model allowed a dependency graph spanning
every platform/region a single Postgres database served, and that part
carries over unchanged.

```json
{"name": "app", "depends_on": [{"platform": "sandbox", "region": "eu-west-1", "name": "compute"}]}
```

Deleting a stack is refused (`409`) while another stack's `DependsOn`, or
any [subscription](subscriptions.md), still references it.

## Triggering reconcile

`SyncID` and `Mode` exist to drive
[subscription reconciliation](subscriptions.md#ongoing-action) — they have
no effect on the stack itself. `Reconciler` never reconciles a subscriber
against a stack whose `SyncID` is empty — there's nothing yet to catch up
to — so `POST /apis/catalog.example.com/v1/stacks` mints one automatically when the request
doesn't name one, same `hashicorp/go-uuid` generator `PUT .../sync` uses.
A request that does name an explicit `sync_id` keeps it as given.

The shorthand:

```bash
curl -s -X PUT http://localhost:8080/apis/catalog.example.com/v1/stacks/compute/sync -H "Authorization: Bearer $TOKEN"
```

stamps a fresh [`hashicorp/go-uuid`](https://github.com/hashicorp/go-uuid)-generated
value onto `SyncID` — that's the entire trigger. An explicit value is still
settable through the normal `PUT .../stacks/:name` instead, if you'd rather
tag a release id than a random one. `Mode` is read by
[`Reconciler`](subscriptions.md#reconciler) when it reconciles a
subscription against this stack — a free-form key into `reconciler.mode`
in `kayra.yaml` (`"trigger"` and `"api"` in the examples there, but any
name works, since it's just a map), not a fixed set of choices.

### Canary rollout

By default, bumping `SyncID` reconciles every active subscriber at once.
To try a new target against one tenant first:

```bash
curl -s -X PUT http://localhost:8080/apis/catalog.example.com/v1/stacks/compute/sync \
  -H "Authorization: Bearer $TOKEN" -d '{"canary_namespaces": ["sre"]}'
```

mints a fresh `SyncID` same as the plain shorthand, but
[`Reconciler`](subscriptions.md#per-job-locking) only reconciles the named
namespaces — every other active subscriber is left exactly as it was,
visibly pending (`current_sync_id` still behind `expected_sync_id`) until
released. Each namespace named must already be subscribed to the stack
(`404` otherwise, catching a typo before it becomes "nothing reconciled
and I don't know why").

Once satisfied, release the same build to everyone else:

```bash
curl -s -X PUT http://localhost:8080/apis/catalog.example.com/v1/stacks/compute/sync -H "Authorization: Bearer $TOKEN"
```

called again with **no** `canary_namespaces` while a rollout is pending —
this reuses the exact `SyncID` the canary already validated (it does
**not** mint another one) and clears the restriction, so every remaining
subscriber reconciles to that same build. Calling the plain shorthand with
no rollout pending behaves exactly as before canary existed at all: a
fresh `SyncID`, straight to everyone.

`CanaryNamespaces` is pipeline state for an in-progress rollout, not a
spec field: only this endpoint ever sets or clears it, so an unrelated
`PUT .../stacks/:name` mid-rollout (changing `owner`, say) can't silently
finish or restart one.

## Checking sync status

`GET /apis/catalog.example.com/v1/stacks/:name/status` reports the stack's own current
`sync_id` plus every **active** subscription's own sync state against
it, in one call — rather than listing every namespace's
[subscriptions](subscriptions.md) by hand and comparing each one's
`expected_sync_id` yourself. A subscription still pending its initial
activation is omitted: there's no sync state to report for one yet.

```bash
curl -s http://localhost:8080/apis/catalog.example.com/v1/stacks/compute/status -H "Authorization: Bearer $TOKEN"
```

```json
{
  "stack_name": "compute",
  "sync_id": "f872573b-8ad8-9dd5-79f0-234fcb41517e",
  "subscriptions": [
    {"namespace": "sre", "state": "success", "current_sync_id": "f872573b-8ad8-9dd5-79f0-234fcb41517e", "synced": true},
    {"namespace": "apps", "state": "success", "current_sync_id": "old-build", "synced": false}
  ]
}
```
