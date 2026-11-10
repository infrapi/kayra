# Kayra

Authentication, namespace creation and IAM policy service, built on
[`infrapi/lib`](https://github.com/infrapi/lib).

Three resources — cluster-wide **API registrations**, per-tenant
**namespaces**, and the **subscriptions** linking them — sit behind the
same bearer-auth and cluster-RBAC model every other endpoint uses, with
a separate `kayra reconciler` process turning disabled records active.

New here? Start with the [quickstart](docs/getting-started.md) — install,
run, bootstrap a token, and create a tenant end to end with `kayra-cli`.

## Why "Kayra"

In Altai Turkic mythology, Kayra Han, son of Tengri, rose from the
primordial waters, shaped the land and gave each of his sons a realm to
govern. Kayra does the same here: it creates namespaces, decides who
rules what through RBAC, and leaves each API to the team that owns it.

## Two binaries

- **`kayra`** (`cmd/kayra`) — the server: `serve`, `reconciler`,
  `cache clean`, `token mint`. Reads `kayra.yaml` directly; not
  something a plain end user runs.
- **`kayra-cli`** (`cmd/cli`) — the portable client an end user logs in
  with. Never reads `kayra.yaml` or any local config — see the
  [CLI reference](docs/cli.md).

One YAML file configures the server — `app:` (infrapi/lib's shared
`INFRAPI_APP_*` bootstrap config), plus the database backend,
authentication providers and authorization backends. See
[`examples/kayra.yaml`](examples/kayra.yaml) for a fully commented
copy, and [config](docs/packages/config.md) for the full reference.

## Core concepts

- **RBAC** — `Group`/`Role`/`RoleBinding`, cluster- and
  namespace-scoped, gated by real resolved directory groups (never a
  synced membership list). See
  [RBAC & auth](docs/architecture/rbac-and-auth.md).
- **ApiRegistration** — declares that an API group exists and who owns
  it (e.g. "compute.example.com", its long name and id); Kayra never implements the API itself. See
  [API registrations](docs/architecture/api-registrations.md).
- **Namespace** — *is* the tenant, not two things joined by a name.
  See [Namespaces](docs/architecture/namespaces.md).
- **Subscription** — links a namespace to an API registration by name; only
  `kayra reconciler` (a separate process, see
  [Subscriptions & reconciliation](docs/architecture/subscriptions.md))
  ever flips it active.

## Documentation

The full docs live in [`docs/`](docs/index.md): a "where to start" table,
the [architecture](docs/architecture/overview.md) pages, the
[CLI reference](docs/cli.md), one page per [`internal/*` package](docs/index.md#packages)
(package-by-domain: each owns its own types, storage and HTTP handlers),
and [development](docs/development.md) notes.

## License

MIT, see [LICENSE](LICENSE).
