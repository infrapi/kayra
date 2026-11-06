# Kayra

Authentication, namespace creation and IAM policy service, built on
[`infrapi/lib`](https://infrapi.github.io/lib/).

Three resources — cluster-wide **API registrations**, per-tenant
**namespaces**, and the **subscriptions** linking them — sit behind the
same bearer-auth and cluster-RBAC model every other endpoint uses, with
a separate `kayra reconciler` process turning disabled records active.

New here? Start with the [quickstart](https://infrapi.github.io/kayra/getting-started/) — install,
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
  [CLI reference](https://infrapi.github.io/kayra/cli/).

One YAML file configures the server — `app:` (infrapi/lib's shared
`INFRAPI_APP_*` bootstrap config), plus the database backend,
authentication providers and authorization backends. See
[`examples/kayra.yaml`](https://github.com/infrapi/kayra/blob/main/examples/kayra.yaml) for a fully commented
copy, and [config](https://infrapi.github.io/kayra/packages/config/) for the full reference.

## Core concepts

- **RBAC** — `Group`/`Role`/`RoleBinding`, cluster- and
  namespace-scoped, gated by real resolved directory groups (never a
  synced membership list). See
  [RBAC & auth](https://infrapi.github.io/kayra/architecture/rbac-and-auth/).
- **ApiRegistration** — declares that an API group exists and who owns
  it (e.g. "compute.example.com", its long name and id); Kayra never implements the API itself. See
  [API registrations](https://infrapi.github.io/kayra/architecture/api-registrations/).
- **Namespace** — *is* the tenant, not two things joined by a name.
  See [Namespaces](https://infrapi.github.io/kayra/architecture/namespaces/).
- **Subscription** — links a namespace to an API registration by name; only
  `kayra reconciler` (a separate process, see
  [Subscriptions & reconciliation](https://infrapi.github.io/kayra/architecture/subscriptions/))
  ever flips it active.

## Where to start

| I want to... | Go to |
|---|---|
| Run Kayra for the first time | [Getting started](https://infrapi.github.io/kayra/getting-started/) |
| Understand how the pieces fit together | [Architecture overview](https://infrapi.github.io/kayra/architecture/overview/) |
| See who can authenticate and who can manage what | [RBAC & auth](https://infrapi.github.io/kayra/architecture/rbac-and-auth/) |
| Create or update an API registration | [API registrations](https://infrapi.github.io/kayra/architecture/api-registrations/) |
| Create or update a tenant | [Namespaces](https://infrapi.github.io/kayra/architecture/namespaces/) |
| Subscribe a tenant to an API registration, or trigger reconcile | [Subscriptions & reconciliation](https://infrapi.github.io/kayra/architecture/subscriptions/) |
| Run a command (`serve`, `reconciler`, `cache clean`, `token mint`) or use `kayra-cli` | [CLI](https://infrapi.github.io/kayra/cli/) |
| Look up one `internal/*` package's API | [Packages](https://infrapi.github.io/kayra/packages/apiserver/) |
| Build, test, or work on the docs themselves | [Development](https://infrapi.github.io/kayra/development/) |

## Layout

Package-by-domain, not package-by-layer: each package below owns its
own types, storage and HTTP handlers together.

| Package | Owns |
|---|---|
| `internal/config` | Loading and validating `kayra.yaml` |
| `internal/store` | etcd / local storage backend |
| `internal/crypto` | PAT encryption, self-signed JWT signing |
| `internal/oidc` | Discovery/JWKS fetch, caching, own endpoints |
| `internal/authn` | Verifying a bearer token, resolving its user id |
| `internal/authz` | Resolving a user id to groups/attributes (LDAP or fixture) |
| `internal/middleware` | The two gin auth middlewares (general + sysadmin) |
| `internal/rbac` | `Group`/`Role`/`RoleBinding`, cluster + namespace scoped |
| `internal/catalog` | `ApiRegistration`/`Namespace`/`Subscription` + the reconciler |
| `internal/tokenapi` | Personal access token issuance |
| `internal/apiserver` | Wires every package above onto one gin engine |

`cmd/kayra` wires all of it together; `cmd/cli` depends on none of it.

## License

MIT, see [LICENSE](https://github.com/infrapi/kayra/blob/main/LICENSE).
