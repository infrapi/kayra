---
title: middleware
description: "The gin authentication middleware every route sits behind, the caller it puts in the request's context, and the sysadmin group."
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
	Audience      []string // a token of Kayra's authorization server: its aud
	ClientID      string   // and its client_id
	Kind          string   // identity.KindUser, or identity.KindServiceAccount
	TokenID       string   // the personal access token's public id, if it is one
	Scope         *crypto.PatScope // that token's scope, nil when unscoped
}

ac, ok := middleware.GetAuth(c) // read what a prior gate resolved
middleware.SetAuth(c, ac)       // set it directly — tests build a fixed-identity gate this way
```

## AuthOf

```go
ac, ok := middleware.AuthOf(ctx)
```

The caller of a request, from its context: `SetAuth`, which the
authenticator calls, puts the `AuthContext` both in the gin context
(`GetAuth(c)`) and in the request's, for the handlers generated from the
[contracts](../development.md#contracts), which get the context only.

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
— whatever [rbac](rbac.md#personal-access-tokens) captured when the PAT was minted.

### Kayra's own identities

A user id under the reserved `system:` prefix
([identity](identity.md)) is refused, whatever provider resolved it, and
the reserved groups are dropped from a human's groups. A JWT carrying a
`kind` claim is one of Kayra's own identities: `Machine` resolves it (the
router checks that the authorization server's signer signed it, then reads
the service account from the store), and it is refused when `Machine` is
nil.

### Expiry and scope

A PAT whose `ExpiresAt` has passed is refused. `last_used_at` in its index
entry is updated at most once an hour. A scoped PAT sends only a request its
scope grants: an `/apis/` path's API and verb, read as `/check` reads them,
the check itself (which applies the scope to the request it decides), GET
`/apis` and `/oauth2/userinfo`. Anything else gets a `403`.

## The sysadmin group

`SysadminGroupFor(platform)` is `"<platform>-core-sysadmin"`, the default
group of the built-in sysadmin binding when `sysadmin.groups` is empty
([config](config.md)). There is no sysadmin middleware: what a caller may
do on a cluster-scoped resource is [rbac](rbac.md#authorizeclusterrequest)'s
cluster RBAC, the sysadmin binding first.
