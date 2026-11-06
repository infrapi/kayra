# Subscriptions & reconciliation

A `Subscription` links a [namespace](namespaces.md) to an
[API registration](api-registrations.md) by name. Repository and route
code lives in `internal/catalog`, backed by [store](../packages/store.md).

```go
type Subscription struct {
	ApiName       string
	Active        bool   // computed
	State         string // init | success | error | undef — computed
	CurrentSyncID string // computed — the subscription's own last-reconciled-to value
}
```

A subscription carries no platform/region of its own: this deployment runs
in exactly one (`INFRAPI_APP_PLATFORM`/`_REGION`), so "subscribed to vault"
can only ever mean the `vault` in *this* deployment's own platform/region —
there's no second one to disambiguate against.

Every response also carries `expected_sync_id` — the referenced
[API registration](api-registrations.md)'s own, *current* `SyncID`. It is **not** a field on
`Subscription` at all: there's nothing to persist, since it's read fresh
from the api registration on every response. Comparing the two tells you, without a
second request, whether a subscription is reconciled (`current_sync_id ==
expected_sync_id`) or reconcile is pending (they differ, and `kayra
reconciler` hasn't caught up — or can't, see [Reconcile](#reconcile) — yet).
Neither field is ever omitted from a response, empty string rather than
missing when there's nothing to report, so a caller never has to treat
"the key is absent" and "the key is empty" as two different things:

```json
{
  "api": "compute.example.com",
  "active": true,
  "state": "success",
  "current_sync_id": "2026-01-01T00Z",
  "expected_sync_id": "2026-02-01T00Z"
}
```

## Managing one

Full CRUD at `/apis/subscription.example.com/v1/namespaces/:namespace/subscriptions{,/:api}`,
gated by [`Authenticator`](rbac-and-auth.md#two-gates-two-trust-tiers) plus
[`rbac.RequireClusterRBAC(repo, "subscriptions", verb)`](../packages/rbac.md#requireclusterrbac)
— "subscriptions" is just another `resource` value checked against the
same cluster `Role.Rules` [RBAC & auth](rbac-and-auth.md#who-can-manage-a-namespaces-rbac-objects)
describes, so an existing sysadmin role using `resources: ["*"]` already
covers it.

=== "kayra-cli"

    ```bash
    kayra-cli create subscription -n core subscriptions -d '{"api": "compute.example.com"}'
    ```

=== "curl"

    ```bash
    curl -s -X POST http://localhost:8080/apis/subscription.example.com/v1/namespaces/core/subscriptions \
      -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -d '{"api": "compute.example.com"}'
    ```

Create requires only `api`, which must be the registration's **long
name** (`compute.example.com`) — a short name is refused (`400`, the
error names the long one to use when a registration has that
`short_name`); subscribing to an api registration that doesn't exist in
this deployment's scope is rejected (`404`).
`PUT .../subscriptions/:api` is a no-op confirmation — `api` is
fixed by the path and `active`/`state`/`current_sync_id` are computed, so
there's nothing left in the body a caller could legitimately change.

### Forcing a re-sync

=== "kayra-cli"

    ```bash
    kayra-cli update subscription -n sre subscriptions dev.example.com/sync -d '{}'
    ```

=== "curl"

    ```bash
    curl -s -X PUT http://localhost:8080/apis/subscription.example.com/v1/namespaces/sre/subscriptions/dev.example.com/sync \
      -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -d '{}'
    ```

Resets `current_sync_id` to empty — nothing else: `active`/`state` are left
exactly as they were. That's the subscription-level mirror of [an api registration's
own `.../sync` shorthand](api-registrations.md#triggering-reconcile), for forcing one
specific subscription to re-run its reconcile immediately rather than
waiting for its api registration's `SyncID` to move on. The reset write is itself
the entire trigger: `kayra reconciler` picks it up exactly like any other
change to the subscription — sees `current_sync_id` no longer matches
`expected_sync_id`, and reconciles again — so there's no separate
"re-run" action to call.

Gated on its own `resource` value, `"subscriptions/sync"` + verb
`"patch"` — not `"subscriptions"` + `"update"` like the no-op `PUT
.../subscriptions/:api` above — so a role can grant one without the
other: resetting a sync is a meaningfully different capability from
editing a subscription, and `resources: ["*"]` still covers both for an
existing sysadmin role.

## Active/State/CurrentSyncID are computed

None of the three are accepted from the request body, on create or update
— a subscription is always created `Active: false`, `State: "init"`,
`CurrentSyncID: ""`. The only thing that ever moves them is `kayra
reconciler`.

## Reconciler

```bash
kayra reconciler
```

`catalog.Reconciler` is the controller that activates a new namespace or
subscription, and reconciles an already-active subscription when its
api registration's `SyncID` moves on. It runs as its **own** process (see
[the CLI reference](../cli.md#reconciler)), deliberately not a goroutine
inside `kayra serve`: independent lifecycles (a reconciler crash doesn't
take the API down, and vice versa), independent logs, independently
restartable and scalable. Built on
[`store.Store.Watch`](../packages/store.md#watch) — etcd's native MVCC
watch in production, `LocalStore`'s polling fallback in dev.

### Concurrency

Every reconcile/activate operation — each namespace activation, each
subscription activation, each per-subscription reconcile inside
[the ongoing action](#ongoing-action)'s fan-out — runs in its own
goroutine, bounded by one shared pool:

```yaml title="kayra.yaml"
reconciler:
  max_concurrent_reconciles: 30 # the default if omitted
```

Sized at 30 by default (`catalog.DefaultMaxConcurrentReconciles`) so that
bumping an api registration's `SyncID` with hundreds of subscribers doesn't spawn
hundreds of goroutines at once — submission itself blocks once the pool is
full, so the bound holds regardless of how large the fan-out is.
`Reconciler.Run` waits for every in-flight goroutine before returning, so
nothing is still touching the store after it stops.

Each slot in the pool is numbered (`0`..`max_concurrent_reconciles - 1`);
whichever one runs a given operation becomes its `lock_id`, logged on
every line along that operation's reconcile path (see
[Logging](#http-step-pipeline) below) — so concurrent runs within this
process's own logs can be told apart, and correlated with whatever else
that same slot was doing. **This bound is purely local to one process**:
running several `kayra reconciler` processes gives each its own full
`max_concurrent_reconciles` allowance — fleet-wide throughput scales with
how many you run, it isn't split between them.

### Per-job locking

Two different triggers can land on the exact same namespace/api pair at
once *within one process* — an api registration's own `SyncID` bump
([the ongoing action](#ongoing-action)'s fan-out) and that same subscription's own
record being touched (the [initial action](#initial-action)) can both
dispatch a reconcile for it at nearly the same moment. Left uncoordinated,
both would run concurrently: two reconciles racing to call the same HTTP
step pipeline, and potentially persist conflicting results, for what's
really one logical change.

Every unit of work — one namespace's activation, or one subscription's
reconcile — is guarded by a lock keyed by that namespace, or
namespace/api pair, **always**, regardless of store backend: a racing
call doesn't run concurrently, it blocks until the one ahead of it
releases the key, then gets its turn. Once it does, it re-reads the
namespace/subscription fresh rather than trusting the (possibly now
stale) snapshot it was dispatched with — the call ahead of it may have
already finished the exact thing it was about to redundantly repeat, in
which case it simply finds nothing left to do.

This blocking, not skip-and-hope-a-future-event-retries-it, matters
because skipping isn't always safe: a [force re-sync](#forcing-a-re-sync)
PUT racing an already in-flight reconcile for the same subscription is
*itself* the only reason to reconcile again — dropping it on the floor
and trusting some other future event to retry would simply lose it.

Running several reconciler processes against the same etcd cluster raises
the same problem again, cluster-wide: etcd's `Watch` is a broadcast, not
a work queue, so every process observes the identical event stream, and
without coordination every one of them would redundantly run the same
job at once. When the configured [`database`](../packages/config.md)
backend is etcd, the lock above is additionally backed by a per-job etcd
mutex (`store.JobLocker`, using etcd's `concurrency` package: a
`Session`+`Mutex` per job, auto-renewed by the session's lease so a
crashed process's locks free up on their own with no manual TTL
bookkeeping needed) — every reconciler process agrees on which one of them
runs it, and a process that loses the race blocks (retrying the
underlying non-blocking `TryLock` on an interval) until its turn comes,
exactly like the in-process layer.

`LocalStore` (the file-backed `dev: local:` backend) does not implement
`store.JobLocker` — a single dev process has no other process to
coordinate with — so against it only the in-process layer applies, which
is already everything a single process needs.

### Initial action

Every namespace record is activated the same way, unconditionally: once
at startup (a one-time list, since `Watch` only streams *future* changes)
and again on every subsequent write, a namespace still `Active: false` is
activated.

A subscription record goes through the same shared decision — `ensureReconciled`
— the [ongoing action](#ongoing-action) fan-out uses, described below: looked up
against its api registration and reconciled if it isn't already both active and at
that registration's current `SyncID`. For a brand-new subscription that's always
true (`Active: false` can never already match), so in practice this is
what activates it for the first time — stamping `CurrentSyncID` with the
registration's **current** `SyncID` once [reconcile](#reconcile) actually
succeeds, so it starts out already reconciled
(`current_sync_id == expected_sync_id`).

### Ongoing action

The "ongoing" action is the mechanism behind a sentence like *"we bumped
compute's sync id, now reconcile every tenant subscribed to it"*:

1. An operator (or `PUT .../apiregistrations/:name/sync`, see [API registrations](api-registrations.md#triggering-reconcile))
   changes an api registration's `SyncID` to any new value — which is also, from the
   API's point of view, every active subscriber's `expected_sync_id`
   changing at once, with no write to any of them.
2. `Reconciler` observes the api registration write and finds every
   namespace with an **active** subscription to it.
3. Each one whose own `CurrentSyncID` doesn't already match the registration's
   goes through `ensureReconciled` — the exact same decision the
   [initial action](#initial-action) uses: [reconcile](#reconcile), then
   only on success update `CurrentSyncID` to match, closing the gap
   `expected_sync_id` already showed.

```text
ensureReconciled(reg, sub):
  already active and CurrentSyncID == reg.SyncID? ──► nothing to do
  reconcile(reg) fails?                            ──► nothing to do
                                                           (retried next time
                                                            something touches
                                                            this subscription
                                                            or, for a new one,
                                                            its api registration)
  reconcile(reg) succeeds                          ──► CurrentSyncID = reg.SyncID
                                                           (+ Active = true, first time)
```

`State` is **never** touched again once it reaches `success` — the
ongoing action only ever moves `CurrentSyncID` forward, and only once
`reconcile` reports success for it, never ahead of that. A subscription
that isn't active yet is skipped by the *ongoing action*'s fan-out
specifically (step 2 above only looks at active subscriptions) — it's
left entirely to the initial action, so an api registration write alone never retries
one that failed to activate; writing to the subscription's own record
again does (`reconcileExisting` does this for every record,
unconditionally, on every `kayra reconciler` startup). Every write
`Reconciler` makes is idempotent
(`Repository.ActivateSubscription`/`SetSubscriptionSyncID`), so it never
loops back on its own writes even though it observes them through the
same watch.

### Reconcile

`ApiRegistration.Mode` is a free-form key into `reconciler.mode` (`config.ReconcilerConfig.Mode`)
— `"trigger"` and `"api"` in every example here, but any name works,
since it's just a map. There is no fixed enum of valid modes: only an
*empty* mode is ever a problem.

An api registration with **no mode at all** (nothing of its own, and no
`reconciler.default_mode` to fall back to — see below) makes `reconcile`
**fail**, since there's no way to carry out reconciliation without
knowing which pipeline to run. `ensureReconciled` never advances
`CurrentSyncID` — or flips a brand-new subscription to active — when
that happens, so a misconfigured api registration's subscriptions visibly stay
unsynced (`current_sync_id` empty or stale against `expected_sync_id`)
rather than being silently marked done.

If the resolved mode *does* have a name, `reconcile` looks it up in
`reconciler.mode`. A mode with [steps configured](#http-step-pipeline) under
`reconciler.mode.<mode>` runs them for real. Every other non-empty mode
name — including every deployment that hasn't configured
`reconciler.mode` at all yet — falls back to the original placeholder:
log which mode would run, and succeed unconditionally.

An api registration with no `mode` of its own doesn't have to fail forever, though:
`reconciler.default_mode` (see [the CLI reference](../cli.md#reconciler)) gives
`reconcile` something to fall back to —

```yaml title="kayra.yaml"
reconciler:
  default_mode: trigger # any mode name; "api" and "trigger" are just this doc's examples
```

— for every api registration that never sets one, without having to touch each one
individually. An explicit `ApiRegistration.Mode`, when a registration has one, always wins
over the default; only an *absent* one falls back to it.

### HTTP step pipeline

`reconciler.mode.<mode>` is a list of plain HTTP calls — `reconcile`'s real
implementation, once configured, in place of the log-only placeholder:

```yaml title="kayra.yaml"
reconciler:
  mode:
    api:
      - method: post
        endpoint: "https://{{ .Subscription.ShortName }}.local.services/api/v1/namespaces/{{ .Subscription.Namespace }}/sync"
        data:
          sync_id: "{{ .Subscription.ExpectedSyncID }}"
        headers:
          Content-Type: "application/json"
          Authorization: {type: Bearer, value: "yyyyyyyyyyyyyyyy"}
        timeout: "3600s"
        async: true
      - method: get
        endpoint: "https://{{ .Subscription.ShortName }}.local.services/api/v1/namespaces/{{ .Subscription.Namespace }}/sync/{{ .Subscription.ExpectedSyncID }}"
        headers:
          Authorization: {type: Bearer, value: "yyyyyyyyyyyyyyyy"}
        timeout: "3600s"
```

A full worked example, including a GitLab pipeline trigger + poll under
`trigger:`, lives in `examples/kayra.yaml`.

**Templating.** `endpoint`, every `headers` value, and every string
reachable inside `data` — however deeply nested, `data`'s own values, an
object field, an array element, any combination — renders as a Go
[`text/template`](https://pkg.go.dev/text/template) against:

- `.Subscription` — `Api` (the long name), `ShortName` (empty when the registration has none), `Namespace`, `Platform`, `Region`,
  `CurrentSyncID`, `ExpectedSyncID` (all strings; the same values
  [the response's two sync fields](#active-statecurrentsyncid-are-computed)
  expose).
- `.Previous.Outputs` — the *immediately preceding* step's own `outputs`
  (below), empty for the first step.

**`data`** isn't limited to a flat string map: it's JSON-encoded (after
templating) whatever shape YAML gives it — nested objects, arrays of
objects, numbers, booleans. This is what lets, say, GitLab's
pipeline-create API's `variables` (a list of `{key, value}` objects, not
a flat map) work directly:

```yaml
data:
  ref: "{{ .Subscription.Platform }}"
  variables:
    - key: TENANT_NAME
      value: "{{ .Subscription.Namespace }}"
    - key: CHECK_MAX
      value: "50" # a literal with no {{ }} passes through unchanged
```

**Headers.** A value is either a plain string, used verbatim (after
templating), or a `{type, value}` pair rendered as `"<type> <value>"` —
`{type: Bearer, value: "tok"}` becomes `Authorization: Bearer tok`.

**`async`** (default `false`) decides what "this step succeeded" means:

- `false` — the call is made and **awaited for up to `timeout`**. A
  non-2xx response, a timed-out wait, or a transport error fails the
  step, which aborts the rest of the pipeline: `reconcile` fails, and
  (per [above](#reconcile)) the subscription's `current_sync_id` is never
  advanced.
- `true` — the call is made but only waited on for about two seconds
  (`catalog.AsyncStepAckTimeout`) *regardless of `timeout`* — long enough
  to capture a quick response (and its `outputs`) if one arrives, but
  never to block on the operation actually finishing. Whatever happens —
  success, failure, or no response in time — is logged and ignored: the
  pipeline always moves on to the next step, or, with none left,
  succeeds. This is the shape of a trigger-then-poll pair: step 1 kicks
  off a job and doesn't wait for it; step 2 is the actual completion
  check, and — being `async: false` — is what the pipeline really waits
  on.

**`outputs`** names values to pull out of a step's JSON response body,
keyed by whatever name a later step should know them by (e.g.
`PipelineID: ".pipeline_id"`, used downstream as
`{{ .Previous.Outputs.PipelineID }}`). The path is a simple dot path —
object fields and `[n]` array indices (`.items[0].id`) — not a full
JSONPath implementation. A path that doesn't resolve against the response
is skipped rather than erroring.

**Logging.** Every step logs its own result — index, method, rendered
endpoint, whether it's async, how many attempts it took, status code (or
error) and outputs extracted — win or lose, before the pipeline decides
what to do about it. This is the only place an async step's failure is
ever visible in detail: the pipeline itself only logs that it's ignoring
that step's error, never what the error was.

Every reconciler log line along the reconcile path — from the initial
"activated"/"reconciled" decision in [`ensureReconciled`](#initial-action)
down to each individual step above — always carries both `lock_id` and
`sync_id`, regardless of outcome. `sync_id` is the api registration's `SyncID` being
reconciled toward; `lock_id` is the [concurrency slot](#concurrency) (or
[distributed lock](#per-job-locking)) that ran it. Neither is ever
omitted, even on success, specifically so that concurrent or
multi-process activity can be correlated in the logs — "which run touched
this subscription" and "what else was this slot doing at the time" are
both answerable from `grep`.

**`wait`** turns a step from "call once, status 2xx is success" into
"call repeatedly until a condition resolves" — the reason step 2 of both
examples above has one. A status-check endpoint commonly answers `200`
whether the thing it's reporting on is still running, succeeded, or
failed; status code alone can't tell those apart, so `wait` inspects the
JSON response body instead:

```yaml
wait:
  - key: .status
    successes: [done]
    failures: [skipped, canceled, failed]
```

`key` is a dot path (the same format `outputs`, above, uses) into the
response body. On each call: that value landing in
`successes` resolves the step done; landing in `failures` fails the step
immediately, with no further polling; landing in neither — or the
response not parsing as JSON, or `key` not resolving at all — means "not
yet", so the step calls again after `catalog.WaitPollInterval` (5s). This
repeats until one of those happens, or the step's own `timeout` elapses
(a timeout is a failure). `wait` can list more than one condition; every
one of them must resolve to its own `successes` for the step to succeed,
while any single one landing in its own `failures` fails the step right
away, regardless of the others.

`wait` only ever applies to a non-async step — `async: true` is
fire-and-forget by definition, so it's ignored there rather than made to
block on a terminal state.
