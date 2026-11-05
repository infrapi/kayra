# Overview

Kayra is three concerns wired onto one gin engine by
[apiserver.Build](../packages/apiserver.md), each in its own
package-by-domain directory — no shared `models`/`controllers` split, no
layer that doesn't own its own types, etcd persistence and HTTP handlers
together:

```text
request → middleware.Authenticator (or SysadminGate) → route handler
                     │                                       │
          authn + authz + oidc + crypto                rbac / catalog
                     │                                       │
                     └───────────── internal/store ──────────┘
```

## Configuration

One `kayra.yaml`, two things resolved from it:

- `app:` — flattened by `config.AppConfig.ToVariables` and handed to
  [infrapi/lib](https://infrapi.github.io/lib/)'s own
  `libconfig.NewConfigFromMap`/`GetAppConfig`, which still owns the
  `INFRAPI_APP_*` validation rules (required fields, `oneof`/`fqdn`/
  `http_url`/`hostname_port`): name, platform, region, listen address.
  Every package that needs "this instance's own platform/region" (API
  registration addressing, the sysadmin group name) reads the resolved
  `AppConfig`, never a request.
- Everything else — Kayra's own [config](../packages/config.md): the
  storage backend, `authentifications.<name>` (how a bearer token is
  verified and whose claim is the user id) and `authorizations.<name>`
  (LDAP or a dev fixture, how a user id resolves to attributes/groups).

See [Getting started](../getting-started.md) for a runnable pair of files.

## Storage

Everything — [RBAC & Auth](rbac-and-auth.md)'s objects, the catalog
resources below, the PAT keypair, every cache — goes through one
[`store.Store`](../packages/store.md) interface: a real etcd cluster in
production, a directory of files for the `dev: local:` backend. One
`Keys` builder gives every package's etcd layout a single source of truth,
and `store.Store.Watch` (etcd's native MVCC watch, or a polling fallback
locally) is what lets a component react to changes instead of polling the
API.

## Catalog

The business domain: cluster-wide **API registrations**, per-tenant
**namespaces**, and the **subscriptions** linking them — ported from the
legacy Postgres/GORM tool, now etcd-backed. Split across
three pages, since each has its own management story:

- [API registrations](api-registrations.md) — records declaring that an
  API group exists and who owns it; Kayra never implements the API
  itself.
- [Namespaces](namespaces.md) — the legacy model's "Tenant".
- [Subscriptions & reconciliation](subscriptions.md) — the link between
  them, plus `kayra reconciler`, the controller that activates and
  reconciles everything above.

`internal/catalog` depends on [rbac](../packages/rbac.md) for exactly one
check (`rbac.RequireClusterRBAC`); rbac has no knowledge of catalog at all.

## Authentication & authorization

See [RBAC & Auth](rbac-and-auth.md) for the full story: how a bearer token
(JWT or PAT) is verified and resolved to a user, how the privileged
`$platform-core-sysadmin` bootstrap credential is produced and checked, and
how Kayra's own stored `Group`/`Role`/`RoleBinding` objects decide who can
manage what.

## Operational processes

Two independent invocations of the one binary, not one process doing both
jobs:

```bash
./kayra serve      # the HTTP API
./kayra reconciler # the catalog reconcile controller
```

See [the CLI reference](../cli.md) and
[Subscriptions & reconciliation](subscriptions.md#reconciler) for why
they're kept apart.
