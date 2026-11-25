---
title: system
description: Serves the system group from its contract - the namespaces, and who sees which.
weight: 135
---

# system

```go
import "github.com/infrapi/kayra/internal/system"
```

Serves Kayra's system API, `/apis/system.infrapi.io/v1/namespaces`, from its
contract, [`api/system-v1.yaml`](../development.md#contracts): the
[namespaces](../architecture/namespaces.md), the unit of isolation every
other API's resources, RBAC and subscriptions live in. The namespaces
themselves are stored by the catalog's `Repository`.

```go
routes := engine.Group("", httpapi.WithRequest, authenticator.Middleware())
system.Register(routes, system.NewServer(catalogRepo, rbacRepo))
```

| Route | |
|---|---|
| `GET …/namespaces` | The namespaces the caller sees, by name. |
| `POST …/namespaces` | `{"name"}` → `201`: a namespace, inactive until the reconciler provisions it. |
| `GET …/namespaces/{namespace}` | A namespace, for the cluster RBAC's readers and its members. |
| `DELETE …/namespaces/{namespace}` | Deletes it. |

- **Writes** (create, delete) are decided on the cluster RBAC,
  [`rbac.AuthorizeClusterRequest`](rbac.md#authorizeclusterrequest), the
  built-in sysadmin binding first.
- **Reads:** whoever the cluster RBAC grants `list` (or `get`) on
  `namespaces` sees every namespace; anyone else the namespaces they are a
  member of, whatever their roles there. Getting one they are not a member
  of is a `403`, with how to become one as its `solution`.
- `active` is set by the reconciler only: the contract marks it `readOnly`,
  and a request sending it is a `400`.
