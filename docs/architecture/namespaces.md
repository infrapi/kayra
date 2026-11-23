---
title: Namespaces
description: "A namespace, Kayra's unit of isolation: its name and active state on one record in internal/catalog."
weight: 40
---

# Namespaces

A `Namespace` is Kayra's unit of isolation: every API's resources, the
RBAC that grants them, the subscriptions and the events live in one. It is
not a tenant: a tenant (a team, a customer) owns one or several namespaces
(see [Multi-tenancy](multi-tenancy.md)). Its name and whether it's active
both live directly on the one record. Repository and route code lives
in `internal/catalog`, backed by [store](../packages/store.md).

```go
type Namespace struct {
	Name   string
	Active bool // computed — see Subscriptions & reconciliation
}
```

## Managing one

`POST /apis/system.infrapi.io/v1/namespaces` (body `{name}`) creates it directly. Full CRUD at `/apis/system.infrapi.io/v1/namespaces`
(collection) and `/apis/system.infrapi.io/v1/namespaces/:namespace` (one), decided on the
[cluster RBAC](auth/rbac-and-auth.md#who-decides) — same as
[ApiRegistration](api-registrations.md), since creating a namespace can't depend on a
cluster `RoleBinding` scoped to a namespace that doesn't exist yet.

> [!TIP]
> The commands below use `infrapi-cli`: [install it](https://infrapi.github.io/cli/getting-started/#1-install).

**infrapi-cli**

```bash
infrapi-cli create namespaces -d '{"name": "core"}'
```

**curl**

```bash
curl -s -X POST http://localhost:8080/apis/system.infrapi.io/v1/namespaces \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "core"}'
```

## Reading them

Anyone authenticated reads the namespaces they are in, whatever their
roles there: one of the namespace's own groups names them or one of their
resolved groups (the ones `member_regex` kept), or a cluster group scoped
to it does, its admins'. Listing answers those only; getting another one
is refused, `403`. Whoever the cluster RBAC grants `get` or `list` on
`namespaces` (the sysadmin binding, a global binding) reads every one.

**infrapi-cli**

```bash
infrapi-cli get namespaces            # the ones you are in
infrapi-cli get namespaces acme  # yours: 200; another: 403
```

**curl**

```bash
curl -s http://localhost:8080/apis/system.infrapi.io/v1/namespaces \
  -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:8080/apis/system.infrapi.io/v1/namespaces/acme \
  -H "Authorization: Bearer $TOKEN"
```

`/check`, and so `infrapi-cli auth can-i`, agree: `list` on `namespaces` is
allowed to anyone, `get` to a member of at least one.

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
