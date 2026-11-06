# Namespaces

A `Namespace` **is** the legacy model's "Tenant" — not two
things joined by a name, one thing: its name and whether it's active
both live directly on the one record. Repository and route code lives
in `internal/catalog`, backed by [store](../packages/store.md).

```go
type Namespace struct {
	Name   string
	Active bool // computed — see Subscriptions & reconciliation
}
```

## Managing one

`POST /apis/apps.example.com/v1/namespaces` (body `{name}`) creates it directly — no
separate `/tenant` child resource. Full CRUD at `/apis/apps.example.com/v1/namespaces`
(collection) and `/apis/apps.example.com/v1/namespaces/:namespace` (one), gated by
[`SysadminGate`](rbac-and-auth.md#two-gates-two-trust-tiers) — same trust
tier as [ApiRegistration](api-registrations.md), since creating a namespace can't depend on a
cluster `RoleBinding` scoped to a namespace that doesn't exist yet.

=== "kayra-cli"

    ```bash
    kayra-cli create apps namespaces -d '{"name": "core"}'
    ```

=== "curl"

    ```bash
    curl -s -X POST http://localhost:8080/apis/apps.example.com/v1/namespaces \
      -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -d '{"name": "core"}'
    ```

`PUT` is a no-op confirmation kept for API shape compatibility: the path
segment is the only thing that ever identified a namespace, and
name/active are both fixed/computed, so there is nothing left in the
body a caller could legitimately change.

## Active is computed

`active` is absent from the create/update request body entirely — there is
no field a client can set to make a namespace come back active. A
namespace is always created disabled; the only thing that ever flips it is
`kayra reconciler`'s initial activation pass — see
[Subscriptions & reconciliation](subscriptions.md#reconciler) for the full
mechanism (the same controller handles both resources, since both are
"computed, activated once observed").
