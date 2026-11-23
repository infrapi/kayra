---
title: tokenapi
description: "A user's personal access tokens - opaque, expiring, optionally scoped - created, listed and revoked by their public id."
weight: 140
---

# tokenapi

```go
import "github.com/infrapi/kayra/internal/tokenapi"
```

Serves a user's [personal access tokens](../architecture/tokens.md) at
`/apis/authorization.infrapi.io/v1/tokens`. The tokens are opaque, not JWTs,
so the store alone never reveals what they are.

```go
tokenapi.RegisterRoutes(engine, authenticator.Middleware(), tokenapi.Options{
	Root: "/apis/" + rbac.AuthorizationAPI + "/v1", Store: s, Keys: keys, Pub: &patKey.PublicKey,
	Config: cfg, TTLs: patTTLs, CanManageOthers: canManage,
})
```

| Route | |
|---|---|
| `POST …/tokens` | `{"name", "expires_in", "scope"}` → `201` with the token, shown once. |
| `GET …/tokens` | The caller's tokens, never a secret. |
| `DELETE …/tokens/{id}` | Revokes it: its record and its index entry are deleted. |

- **Who may create one:** only a user logged in. A PAT cannot create one
  (`403 a personal access token creates no other`), and neither can one of
  Kayra's own identities (`system:…`).
- **Another user's tokens:** `?user=` on the list or the delete reads or
  revokes another user's tokens when `CanManageOthers(ac, verb)` allows it.
  `apiserver.Build` passes the cluster RBAC's `tokens` `list` or `delete`.
- **The record:** [`crypto.PatRecord`](crypto.md#pat-records) is encrypted
  under `Pub` at `keys.PatToken(crypto.HashToken(token))`. Its index entry
  ([`crypto.PatIndexEntry`](crypto.md#pat-records)) lives at
  `keys.PatIndex(user, id)`. Both are written with the token's TTL, so an
  expired token leaves nothing behind.
- **Roles:** the token always inherits its user's live roles, resolved at use
  time by [`middleware.Authenticator`](middleware.md#authenticator). The one
  exception is a `claims`-backed authorization backend (see
  [config](config.md#claims-no-directory-at-all)), where the record keeps a
  snapshot of the groups and attributes from the creation.
