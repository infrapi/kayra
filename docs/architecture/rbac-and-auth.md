---
title: "RBAC & auth"
description: How a request is authenticated and how Kayra decides what the caller is allowed to do.
weight: 20
---

# RBAC & auth

How a request becomes "this is `jdoe`, authenticated via `okta`", and how
Kayra then decides what `jdoe` is allowed to do. Package references:
[authn](../packages/authn.md), [authz](../packages/authz.md),
[oidc](../packages/oidc.md), [crypto](../packages/crypto.md),
[middleware](../packages/middleware.md), [rbac](../packages/rbac.md).

## Two gates, two trust tiers

Every route sits behind one of two gin middlewares
([middleware.Authenticator](../packages/middleware.md#authenticator) or
[middleware.SysadminGate](../packages/middleware.md#sysadmingate)), never
both:

| Gate | Accepts | Used by |
|------|---------|---------|
| `Authenticator` | any configured `authentifications.<name>` provider, or a PAT | namespace-scoped routes (rbac, subscriptions), `/oauth2/userinfo`, `POST /apis/authorization.example.com/v1/check`, `POST /api/v1/tokens` |
| `SysadminGate` | **only** local signing keys, requiring the `<platform>-core-sysadmin` group claim | `/apis/authorization.example.com/v1/cluster*`, the namespace collection (`/apis/system.example.com/v1/namespaces`) |

## Verifying a bearer token

```text
Authorization: Bearer <token>
        │
        ├─ starts with "pat_"? ─────────────► decrypt + look up PatRecord
        │                                              │
        └─ otherwise, parse as JWT                     │
                 │                                      │
        read kid header, oidc.Manager.FindKey(kid)      │
                 │                                      │
        verify signature, iat not future, exp not past  │
                 │                                      │
        resolve user id (claim, or call userinfo_endpoint)
                 │                                      │
                 └──────────────► authz.Cached.ResolveUser(userID) ◄┘
                                          │
                                   AuthContext{UserID, Groups, ...}
```

A PAT record carries no groups of its own
([crypto.PatRecord](../packages/crypto.md#pat-records)) — both paths end at
the same `authz.Cached.ResolveUser` call, so a caller's roles are always
resolved **live** from their current group membership, never snapshotted
at token-mint time. [`oidc.Manager.FindKey`](../packages/oidc.md#manager)
checks local (self-signed) providers first, then every remote provider's
JWKS **cache**, only refreshing a cache when no provider's held cache has
the `kid` — the spec's "absent from cache -> refresh, otherwise don't"
rule. Resolved users and fetched JWKS both live in the store with a TTL —
see [`kayra cache clean`](../cli.md#cache-clean).

## Bootstrapping with SysadminGate

The `/apis/authorization.example.com/v1/cluster*` endpoints (and the
namespace collection) require the caller's resolved groups to intersect a
configured sysadmin group list
([config.SysadminConfig.Groups](../packages/config.md)) — authored directly
in `kayra.yaml` as real LDAP/IdP group names, defaulting to a single
group, `<platform>-core-sysadmin`, only when left empty (`$platform` is a
template, rendered with this instance's own configured
`INFRAPI_APP_PLATFORM`, so on a `sandbox` deployment the default is
`sandbox-core-sysadmin`).

[`middleware.SysadminGate`](../packages/middleware.md#sysadmingate)
authenticates exactly the way any other endpoint does — a self-signed
local JWT, a remote provider's token (Okta, say), or a PAT, all resolved
through the same `Authenticator.resolveJWT`/`resolvePAT` — and then
checks that privilege list; the groups claim itself is never typed in by
an operator, whichever path resolves it: a real authorization backend's
live lookup, or (for a claims-backed `authorizations.<name>`) straight out
of the caller's own already-verified token/userinfo.

```bash
kayra-cli login --server https://kayra.example.com
```

## The RBAC model

```go
type Group struct {
	Name     string
	Metadata Metadata // Namespace, Region, Platform
	Groups   []string // resolved group names, e.g. "sandbox-core-sysadmin"
	Users    []string // resolved user ids, e.g. "ahdemir"
}
type Role struct {
	Name     string
	Metadata Metadata
	Rules    []Rule // Apis, Resources, Verbs — each wildcardable with "*"
}
type RoleBinding struct {
	Name     string
	Metadata Metadata
	Role     string
	Groups   []string
}
```

Cluster-scoped (`/apis/authorization.example.com/v1/{clustergroups,
clusterroles,clusterrolebindings}`, `SysadminGate`) and namespace-scoped
(`/apis/authorization.example.com/v1/namespaces/:namespace/{groups,roles,rolebindings}`,
`Authenticator` + the check below) copies of the same three objects — see
[rbac](../packages/rbac.md#types) for the full field reference. A
`RoleBinding`'s `Role` and every `Group` it names must share its exact
`Metadata` (region/platform/namespace), checked at creation time.

## Who can manage a namespace's RBAC objects

`POST`/`GET`/`PUT`/`DELETE` on a namespace's `groups`/`roles`/`rolebindings`
— and, via the identical check, a namespace's
[subscriptions](subscriptions.md) — require more than just being
authenticated: either one of the caller's own resolved groups (the same
`groups` field `/oauth2/userinfo` returns) must be listed in a
**cluster**-level `Group`'s own `groups`, or their own user id must be
listed in its `users` — and that `Group` must be bound by a cluster
`RoleBinding` scoped to that exact
namespace, to a cluster `Role` granting
`apis: ["authorization.example.com"]` (groups/roles/rolebindings) or
`apis: ["catalog.example.com"]` (subscriptions) for the relevant
verb — evaluated in
[`rbac.Repository.CanManageNamespaceRBAC`](../packages/rbac.md#canmanagenamespacerbac).
This is exactly the spec's cluster bootstrap flow (group → role →
rolebinding), now actually enforced rather than only ever written. A
denial's `detail` names which step failed: no matching group, no
rolebinding for this namespace, or a role that doesn't grant the verb.

Both groups split the same way: their namespace-scoped resources are
gated by these rules, their cluster-scoped ones (`clustergroups`/
`clusterroles`/`clusterrolebindings`, `apiregistrations`) by
`SysadminGate` alone. So `resources: ["*"]` on `catalog.example.com`
grants subscriptions only, never apiregistrations — just as `"*"` on
`authorization.example.com` never grants cluster roles.

This check is **not** based on a synced group membership list — there is
no `/refresh` action and no "members" record anywhere in Kayra.
Authorization checks the caller's own already-resolved groups (and user
id) directly: real LDAP directories commonly nest groups inside groups
(a group's `member` attribute listing other group DNs, not user DNs),
so a flat synced member list could never reliably contain the calling
user — but `memberOf` (what authn resolves `groups` from at login,
`cn=...` DNs stripped down to their short name by `member_regex`,
see [config](../packages/config.md#authorizations)) already reflects the
full nested membership. A `Group`'s own `groups` is authored in that
same already-resolved vocabulary (plain names, never raw DNs), so
there's nothing left to re-derive here — and it isn't scoped by
`authorizations.<name>` backend either: whichever backend actually
resolved the caller, their resolved groups/id are checked against it
regardless. `users` sidesteps group
membership altogether, for access that doesn't warrant (or can't wait
for) a directory group of its own.

## Authorizing other apps' requests

Any app built on `infrapi/lib` exposing routes shaped
`/apis/compute.example.com/v1/namespaces/:namespace/<resource>` can
authorize a request against **that namespace's own**
`Group`/`Role`/`RoleBinding` objects (the ones its admins create via
`RegisterNamespaceRoutes`, once `CanManageNamespaceRBAC` let them in) by
calling Kayra's `POST /apis/authorization.example.com/v1/check`,
gated by `Authenticator` like every other namespace-scoped route:

```json
// request, Authorization: Bearer <the caller's own token>
{"namespace": "core", "api": "compute.example.com", "resource": "vm", "verb": "list"}
// response
{"allowed": true}
```

Every check runs these steps in this order, and the first one that fails
is the answer, so the reason a caller gets is the one that actually blocks
them. Membership comes before anything about the api, so a non-member
learns nothing about what a namespace is subscribed to. The api's OpenAPI
spec comes before roles, so a resource the app doesn't serve is reported as
that, not as an RBAC denial. Steps 1 and 3–7
(`catalog.Repository.CheckNamespace` / `CheckApiSubscription` /
`CheckApiResource`) return a problem-detail error; steps 2, 8 and 9
(`rbac.Repository.NamespaceMembership` / `AuthorizeMember`) return `200`
with `allowed: false` and the reason.

| # | Condition that fails | Answer | Detail |
|---|---|---|---|
| 1 | the namespace doesn't exist | `404` | `namespace "core" not found` |
| 2 | neither the caller's user id nor any of their groups is listed in any of the namespace's own `Group`s | `allowed: false` | `you are not a member of namespace "core": neither your user id nor any of your groups is listed in any of its groups` |
| 3 | no `ApiRegistration` whose long name (its id) is `api` exists in this deployment's platform/region; a short name never matches, and the solution names the long one | `404` | `api "telemetry.infrapi.io" is not registered in sandbox/eu-west-1` |
| 4 | the namespace has no subscription to that registration | `403` | `namespace "core" is not subscribed to api "telemetry.infrapi.io"` (solution: subscribe first) |
| 5 | the subscription is not active: its initial sync hasn't completed, so **every verb is refused**, reads included | `403` | `subscription of namespace "core" to api "telemetry.infrapi.io" is not active yet (state "init"): its initial sync has not completed, so the api is not ready` |
| 6 | the api's [OpenAPI spec](api-registrations.md#openapi-spec) has no namespaced `resource`; a singular/plural slip gets a "did you mean" | `404` | `api "telemetry.infrapi.io" has no resource "dashboard"` (solution: did you mean "dashboards"?) |
| 7 | the spec has `resource`, but not `verb` on it | `405` | `resource "dashboards" of api "telemetry.infrapi.io" doesn't support "delete" (supported: get, list)` |
| 8 | no role bound to the caller's groups grants `api` at all | `allowed: false` | `no role bound to your groups in namespace "core" grants api "telemetry.infrapi.io"` |
| 9 | a role grants `api`, but not `verb` on `resource` | `allowed: false` | `your roles in namespace "core" grant api "telemetry.infrapi.io", but not "list" on "dashboards"` |

An active subscription always has a stored spec, since the sync that
activated it needed one. If one is missing anyway, step 6 answers `503`
rather than letting the request through.

Namespace `Role`s are checked against the same specs when they're created
or updated (`catalog.Repository.ValidateRoleRules`), and a bad rule is
refused with `400`:

- every api must be registered here (by its long name), be one of Kayra's
  own, or be `*`;
- every resource must be a namespaced resource of the api's spec, or `*`;
- every verb must be supported by at least one of the rule's resources, or
  be `*`.

A registered api that has never synced has no spec yet, so its resources
and verbs are accepted as written.

A subscription becomes active once, when its initial sync succeeds, and
never becomes inactive again. When the registration later gets a new
`sync_id`, an active subscription keeps working for every verb even while
its `current_sync_id` is behind (`synced: false`): a `v1` api stays
backward compatible, so the pending re-sync is for the api owner to plan,
not a reason to refuse callers. See
[subscriptions](subscriptions.md#state).

`Namespace`/`Api` come straight from the URL (`Api` is the calling
app's own full API group URN, e.g. "compute.example.com", matching how
it's actually reachable — never the bare app name); `Resource`/`Verb`
are derived from the rest of the path and the HTTP method — verbs match
HTTP methods (`list`/`get` for `GET`, `create` for `POST`, `update` for
`PUT`, `patch` for `PATCH`, `delete` for `DELETE`), and a sub-resource
action is just part of `Resource` (`PATCH .../vm/:id/reboot` → resource
`"vm/reboot"`, verb `"patch"`) — both parsed client-side by
`infrapi/lib`'s `pkg/auth`, since that rule needs no Kayra-specific
knowledge. The actual decision —
[`rbac.Repository.Authorize`](../packages/rbac.md#authorize) — stays
server-side: it's the same group→role→rolebinding evaluation
`CanManageNamespaceRBAC` does, just against the namespace's own RBAC
objects instead of the cluster's, and against an arbitrary API URN
instead of one of Kayra's own two fixed URNs
(`rbac.AuthorizationAPI`/`catalog.CatalogAPI`).
