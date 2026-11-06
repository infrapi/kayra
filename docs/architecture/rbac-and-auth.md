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
| `SysadminGate` | **only** local signing keys, requiring the `<platform>-core-sysadmin` group claim | `/apis/authorization.example.com/v1/cluster*`, the namespace collection (`/apis/apps.example.com/v1/namespaces`) |

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
`apis: ["subscription.example.com"]` (subscriptions) for the relevant
verb — evaluated in
[`rbac.Repository.CanManageNamespaceRBAC`](../packages/rbac.md#canmanagenamespacerbac).
This is exactly the spec's cluster bootstrap flow (group → role →
rolebinding), now actually enforced rather than only ever written. A
denial's `detail` names which step failed: no matching group, no
rolebinding for this namespace, or a role that doesn't grant the verb.

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

Before any RBAC rule is evaluated, every check validates its target
(`catalog.Repository.CheckSubscribedApi`), in
this order, and returns an error instead of a decision on the first
failure:

| Condition | Status | Detail |
|---|---|---|
| the namespace doesn't exist | `404` | `namespace "core" not found` |
| no `ApiRegistration` whose long name (its id) is `api` exists in this deployment's platform/region — a short name never matches | `404` | `api "compute.example.com" not found in sandbox/eu-west-1` |
| the namespace has no subscription to that registration | `403` | `namespace "core" is not subscribed to api "compute.example.com"` |
| the subscription is not active yet (never reconciled) and `verb` is anything but `get`/`list` | `403` | `subscription of namespace "core" to api "compute.example.com" is not active (state "init"): only read verbs (get, list) are allowed until it is reconciled` |

A subscription becomes active only once the Reconciler has provisioned
it; until then the namespace is read-only on that api — every other
verb (`create`, `update`, `patch`, `delete`, or any unknown one) is
refused.

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
(`AuthorizationAPI`/`SubscriptionAPI`).
