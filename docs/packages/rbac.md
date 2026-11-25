---
title: rbac
description: Stores and serves the authorization group, from its contract - cluster and namespace groups, roles and role bindings, service accounts, personal access tokens - and /check.
weight: 120
---

# rbac

```go
import "github.com/infrapi/kayra/internal/rbac"
```

Stores and serves the cluster- and namespace-scoped `Group`/`Role`/
`RoleBinding` objects the spec's bootstrap flow describes, the check
(`CanManageNamespaceRBAC`) that decides who can manage them, and the check
(`Authorize`) any app built on `infrapi/lib` calls to decide what an
already-authenticated caller may do against its own
`/apis/compute.infrapi.io/v1/namespaces/:namespace/<resource>`-shaped routes.

## Types

```go
type Metadata struct {
	Namespace, Region, Platform string
}

type Group struct {
	Name, Description string
	Metadata          Metadata
	Groups            []string // resolved group names, e.g. "sandbox-core-sysadmin" — matched against the caller's resolved groups
	Users             []string // resolved user ids, e.g. "ahdemir" — matched against the caller's own resolved user id
	ServiceAccounts   []string // a namespace group only: its namespace's service accounts, by name
	APIs              []string // registered APIs, by group, exactly: system:api:<group> is a member
}

type ServiceAccount struct {
	Name, Description string
	Metadata          Metadata
	UID               string // set at creation, never changed: its tokens carry it
}

type Rule struct {
	Apis, Resources, Verbs []string // each wildcardable with "*"; Apis is the full API group URN, e.g. "compute.infrapi.io"
}

type Role struct {
	Name, Description string
	Metadata          Metadata
	Rules             []Rule
}

type RoleBinding struct {
	Name, Description string
	Metadata           Metadata
	Role               string
	Groups             []string
}
```

A `Group` names external directory membership directly on itself, not a
locally synced member list — see
[CanManageNamespaceRBAC](#canmanagenamespacerbac) for why. `Groups`
names real directory groups, `Users` names specific people directly —
for access that doesn't warrant (or can't wait for) a directory group
of its own. Either list alone is enough; a `Group` can use one, the
other, or both. Both lists hold the same already-resolved vocabulary
`authz.UserInfo` produces (plain names/ids, e.g. "sandbox-core-sysadmin"
or "ahdemir"), **never** raw directory syntax like an LDAP DN — see
[config](config.md#authorizations) for how
`authorizations.<name>.ldap.user.groups.member_regex` extracts that
short name out of a real group DN at login time, so there's nothing
left to re-derive here. Not scoped by `authorizations.<name>` backend
either: whichever backend actually resolved the caller, their resolved
groups/id are checked against this same `Group` regardless. A
`RoleBinding` grants one `Role` to a set of `Group`s, all at the same
`Metadata` scope.

```json
{
  "name": "core-group-sysadmin",
  "metadata": {"namespace": "core", "region": "eu-west-1", "platform": "sandbox"},
  "groups": ["sandbox-core-sysadmin"],
  "users": ["ahdemir"]
}
```

## Routes

The rbac API's routes, the authorization group's, are generated from its
contract, [`api/rbac-v1.yaml`](../development.md#contracts):
`zz_generated.go` has `Handlers`, one method per operation, and `Register`.
`Server` implements them, deciding each request in the method itself:

```go
repo.SetSysadmin(sysadminGroups) // the built-in sysadmin binding
routes := engine.Group("", httpapi.WithRequest, authenticator.Middleware())
rbac.Register(routes, rbac.NewServer(rbac.ServerOptions{
	Repo:                     repo,
	ValidateClusterRoleRules: validateClusterRules, // a global cluster role's rules
	ValidateRoleRules:        validateRules,        // a namespace role's; may be nil
	Tokens:                   rbac.ServiceAccountTokens{Issuer: as, DefaultTTL: time.Hour, MaxTTL: 24 * time.Hour},
	Prechecks:                rbac.Prechecks{Namespace: ..., Api: ..., Resource: ...},
	Auditor:                  auditor,
	PATs:                     rbac.PATOptions{Store: s, Keys: keys, Pub: &patKey.PublicKey, Config: cfg, TTLs: patTTLs, CanManageOthers: canManage},
}))
```

The request bodies and answers are the contract's types (package `api`),
converted to and from the stored ones with
[`httpapi.Convert`](httpapi.md#context-and-conversion). The contract is
checked before a method runs: a field it marks `readOnly` (`uid`,
`created_at`) in a request is a `400`, and so is a key of a `jwks` with a
private member, `d` (its `JWK` schema allows no other property).

- **Cluster** — full CRUD at
  `/apis/authorization.infrapi.io/v1/{clustergroups,clusterroles,
  clusterrolebindings}`, decided by [`AuthorizeClusterRequest`](#authorizeclusterrequest):
  the cluster RBAC they define decides who manages them, the built-in
  sysadmin binding first, which no stored object can lock out. Writes
  follow the [anti-escalation rule](../architecture/auth/rbac-and-auth.md#anti-escalation).
- **Namespace** — full CRUD at
  `/apis/authorization.infrapi.io/v1/namespaces/:namespace/{groups,roles,rolebindings}`,
  decided by
  [`AuthorizeNamespaceRBAC(ctx, namespace, api, resource, verb)`](#authorizenamespacerbac)
  in each method (`api` is `AuthorizationAPI` here) — a caller must
  already hold cluster-level rights over that exact namespace before
  touching its namespace-scoped defaults. `AuthorizeNamespaceRBAC` is
  exported so `internal/catalog` decides its own namespace-scoped
  [Subscription](../architecture/subscriptions.md) routes through the
  identical check, against `catalog.CatalogAPI` instead. A namespace
  `Role`'s rules go through `validateRules` on create and update when one
  is given; `apiserver.Build` passes `catalog.Repository.ValidateRoleRules`,
  which checks them against each api's OpenAPI spec (see
  [RBAC & auth](../architecture/auth/rbac-and-auth.md#authorizing-other-apps-requests)).
- **Authorize** — `POST /apis/authorization.infrapi.io/v1/check`,
  `Server.Check`, for any authenticated caller (any configured provider),
  never by `Allows` against that same api group — the general-purpose
  decision endpoint any app built on `infrapi/lib` calls, deciding only
  ever on behalf of the caller's own already-resolved identity, exactly
  like Kubernetes' `SelfSubjectAccessReview` needs no RBAC grant of its
  own — see [Authorize](#authorize).

- **Service accounts** — CRUD at
  `/apis/authorization.infrapi.io/v1/namespaces/:namespace/serviceaccounts`,
  decided as the namespace's other objects are (`AuthorizeNamespaceRBAC`), and
  the token action `POST .../serviceaccounts/{serviceaccount}/token`, a permission of
  its own (`serviceaccounts/token`, `create`). Its `TokenIssuer` is the
  authorization server; without one, the action answers `501`. See
  [Service accounts](../architecture/auth/service-accounts.md).
  `repo.ServiceAccountContext(subject, uid)` resolves a token of one, the
  authenticator's `Machine`. A service account is counted only by a group of
  its own namespace: by name in `ServiceAccounts`, or through
  `system:serviceaccounts:<ns>` in `Groups`, never by a wildcard.
  `clusterGroupsMatching`, `ClusterRules`, `CanManageNamespaceRBAC` and
  `scopedNamespaces` never count one.
- **APIs** — an API's identity, `system:api:<group>`, is counted by a
  group, cluster or namespace, that names it in `APIs`, exactly; no other of
  Kayra's own identities is ever matched. `ImplicitAPI(caller, api,
  resource, verb, name)` is what an API may always do about itself: get its
  own `apiregistrations` and `apiregistrations/status`. `AuthorizeClusterRequest`
  (the route's `name`) and `/check` (a request's `name`) apply it before the RBAC. See
  [API identity](../architecture/auth/api-identity.md).

A group's members are checked on create and update: no reserved
(`system:`) user, no reserved group but a namespace group's own
`system:serviceaccounts:<ns>`, no service account in a cluster group, and no
`apis` entry that is not an API group (no wildcard).

A `RoleBinding`'s `Role` and every `Group` it names must share its exact
`Metadata` (checked on create/update) — region, platform and namespace all
have to agree, "works only if region, platform and namespace match
obviously."

## CanManageNamespaceRBAC

```go
allowed, reason, err := repo.CanManageNamespaceRBAC(userID, callerGroups, namespace, api, resource, verb)
```

The spec's cluster bootstrap flow, actually enforced: either one of
`callerGroups` (the caller's own already-resolved groups — the same
`groups` [`/oauth2/userinfo`](oidc.md) returns) must be listed in a
cluster `Group`'s own `Groups`, or `userID` must be listed in its
`Users`, and that `Group` must be bound by a cluster `RoleBinding`
scoped to `namespace`, to a cluster `Role` granting `apis: [api]` for
`verb` on `resource`. In practice `api` is always one of the two fixed
constants `AuthorizeNamespaceRBAC`'s callers pass: `AuthorizationAPI` for
resource `"groups"`/`"roles"`/`"rolebindings"`, `catalog.CatalogAPI` for
`"subscriptions"`/`"subscriptions/sync"`.
A denial's `reason` names which step failed: no matching group, no
rolebinding for this namespace, or a role that doesn't grant the verb.

Not based on a synced membership list — there is no `/refresh` action
and no "members" record anywhere in Kayra. Real LDAP directories
commonly nest groups inside groups (a group's `member` attribute listing
other group DNs, not user DNs), so a flat synced list could never
reliably contain the calling user — but the groups authn resolved for
this caller at login time (via `memberOf`) already reflect that full
nested membership, so matching against those directly, rather than
re-deriving directory membership here, sidesteps the problem entirely.
`Users` sidesteps group membership altogether, for access that doesn't
warrant (or can't wait for) a directory group of its own.

## Authorize

```go
allowed, reason, err := repo.Authorize(userID, callerGroups, namespace, api, resource, verb)
```

`CanManageNamespaceRBAC`'s general-purpose twin: the same
direct-user-or-group→role→rolebinding evaluation, but against
`namespace`'s **own**
`Group`/`Role`/`RoleBinding` objects (what that namespace's admins create
through the [namespace routes](#routes), once `CanManageNamespaceRBAC` let
them in) instead of the cluster's, and against an arbitrary `api` —
that calling app's own full API group URN, e.g. "compute.infrapi.io",
never the bare app name — instead of one of Kayra's own two fixed
URNs. This is what backs `POST /apis/authorization.infrapi.io/v1/check`
([`Server.Check`](#routes)) — the one call `infrapi/lib`'s
`pkg/auth` makes to authorize a request on behalf of any app built on
top of it, without that app storing or evaluating RBAC rules itself.
See
[RBAC & auth](../architecture/auth/rbac-and-auth.md#authorizing-other-apps-requests).

## AuthorizeNamespaceRBAC

```go
if err := repo.AuthorizeNamespaceRBAC(ctx, namespace, catalog.CatalogAPI, "subscriptions", "create"); err != nil {
	return api.Subscription{}, err
}
```

Wraps `CanManageNamespaceRBAC` for one `api`/`resource`/`verb` triple, the
caller read from the request's context ([`middleware.AuthOf`](middleware.md#authof)).
Denies with `403` and the check's `reason` in `detail`, `401` without a
caller (`Caller(ctx, origin)`).

## AuthorizeClusterRequest

`repo.AuthorizeClusterRequest(ctx)` decides a cluster-scoped request: its
api, resource and verb are read from its path and method
([`httpapi.RequestOf`](httpapi.md#context-and-conversion)) as infrapi/lib
reads them (`ClusterRequest`), then decided by `ImplicitAPI` (the route's
`name`) and `AuthorizeCluster` — what `/check` answers for the same request.

## AuthorizeCluster

`AuthorizeCluster(userID, groups, api, resource, verb)` decides a
cluster-scoped resource on `ClusterRules`: the built-in sysadmin binding's
`*` (`SetSysadmin`), and the cluster roles of the global bindings
(`metadata.namespace: ""`) of the global cluster groups the caller is a
member of. A binding scoped to a namespace never counts here, and a global
one never counts in a namespace.

## Anti-escalation

`Uncovered(have, want)` is the first permission `want` grants that `have`
does not. A cluster role or binding write is checked against
`ClusterRules`, a namespace one against `NamespaceRules` (the cluster
bindings scoped to the namespace, and the caller's own rolebindings
there), unless the caller holds `escalate` on the roles resource, or
`bind` on the rolebindings one.

## Personal access tokens

A user's [personal access tokens](../architecture/auth/tokens.md), at
`/apis/authorization.infrapi.io/v1/tokens`, are `Server`'s too, from
`ServerOptions.PATs`. The tokens are opaque, not JWTs, so the store alone
never reveals what they are.

| Route | |
|---|---|
| `POST …/tokens` | `{"name", "expires_in", "scope"}` → `201` with the token, its secret (`token`) shown once. |
| `GET …/tokens` | The caller's tokens, oldest first, never a secret. |
| `GET …/tokens/{id}` | One of them, without its secret; `404` when there is none. |
| `DELETE …/tokens/{id}` | Revokes it: its record and its index entry are deleted. |

- **Who may create one:** only a user logged in. A PAT cannot create one
  (`403 a personal access token creates no other`), and neither can one of
  Kayra's own identities (`system:…`).
- **Another user's tokens:** `?user=` on the list, the get or the delete
  reads or revokes another user's tokens when `PATs.CanManageOthers(ac,
  verb)` allows it, `verb` being `list`, `get` or `delete`.
  `apiserver.Build` passes the cluster RBAC's `tokens` and that verb.
- **The record:** [`crypto.PatRecord`](crypto.md#pat-records) is encrypted
  under `PATs.Pub` at `keys.PatToken(crypto.HashToken(token))`. Its index
  entry ([`crypto.PatIndexEntry`](crypto.md#pat-records)) lives at
  `keys.PatIndex(user, id)`. Both are written with the token's TTL, so an
  expired token leaves nothing behind.
- **Roles:** the token always inherits its user's live roles, resolved at use
  time by [`middleware.Authenticator`](middleware.md#authenticator). The one
  exception is a `claims`-backed authorization backend (see
  [config](config.md#claims-no-directory-at-all)), where the record keeps a
  snapshot of the groups and attributes from the creation.
