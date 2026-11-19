---
title: middleware
description: "The two gin middlewares every route sits behind: bearer authentication and the sysadmin gate."
weight: 80
---

# middleware

```go
import "github.com/infrapi/kayra/internal/middleware"
```

Wires [authn](authn.md), [authz](authz.md) and [crypto](crypto.md) together
into the two gin middlewares every HTTP route sits behind: general bearer
auth (any configured provider, PAT included), and the privileged sysadmin
gate for the cluster bootstrap endpoints.

## AuthContext

```go
type AuthContext struct {
	UserID        string
	Provider      string
	Authorization string
	Attributes    map[string]string
	Groups        []string
}

ac, ok := middleware.GetAuth(c) // read what a prior gate resolved
middleware.SetAuth(c, ac)       // set it directly — tests build a fixed-identity gate this way
```

## Authenticator

```go
auth := &middleware.Authenticator{
	Manager: manager, Config: cfg, Backends: backends,
	Store: s, Keys: keys, PatKey: patKey, DefaultTTL: time.Hour,
}
engine.Use(auth.Middleware())
```

`Middleware()` reads the `Authorization: Bearer` header and branches on
shape: a token starting with `crypto.TokenPrefix` (`"pat_"`) is looked up
and decrypted ([crypto.DecryptRecord](crypto.md#pat-records)); anything
else is parsed and verified as a JWT ([authn.Verify](authn.md#verify)).
On success the `AuthContext` is stored for downstream handlers; on any
failure the request is aborted with `401`.

A JWT's provider maps to its `authentifications.<name>` entry to find
which `authorizations.<name>` backend resolves it, and (for a `remote`
provider) its `user_id` rule
([authn.ResolveUserID](authn.md#resolveuserid)); a `local` provider with no
explicit rule defaults to reading `sub` directly from the token. From
there, Groups/Attributes come from one of two places depending on that
backend's own kind:

- `ldap`/`local` — the matching `authorizations.<name>` backend
  ([authz.Cached.ResolveUser](authz.md#cached)), by bare user id —
  never from the token itself.
- `claims` (see [config](config.md#claims-no-directory-at-all)) — this
  same already-verified token's own claims or userinfo response
  ([authn.ResolveGroups](authn.md#resolvegroups)/[ResolveAttributes](authn.md#resolveattributes)),
  with no directory lookup at all; `Backends` carries no entry for this
  name (see [apiserver.Build](apiserver.md)), so this path never
  touches it.

A PAT carries no groups of its own — only `UserID`/`Authorization`/
`Provider`(/`SnapshotGroups`/`SnapshotAttributes`)
([crypto.PatRecord](crypto.md#pat-records)). For an `ldap`/`local`
backend, every PAT request still resolves live groups from the backend,
meaning a token "inherits all roles where I'm a member of group" at
request time, never a snapshot taken when the token was minted. For a
`claims`-backed one, there is no directory left to re-query by bare user
id, so `resolvePAT` reads `SnapshotGroups`/`SnapshotAttributes` instead
— whatever [tokenapi](tokenapi.md) captured when the PAT was minted.

## The sysadmin group

`SysadminGroupFor(platform)` is `"<platform>-core-sysadmin"`, the default
group of the built-in sysadmin binding when `sysadmin.groups` is empty
([config](config.md)). There is no sysadmin middleware: what a caller may
do on a cluster-scoped resource is [rbac](rbac.md#requirecluster)'s
cluster RBAC, the sysadmin binding first.
