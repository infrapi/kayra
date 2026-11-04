# Kayra

Authentication, namespace creation and IAM policy service, built on
[`github.com/infrapi/lib`](https://github.com/infrapi/lib).

New here? Start with the [quickstart](docs/getting-started.md) — build,
run, bootstrap a token, and create a tenant end to end with `curl`.

## Build & test

```bash
go build ./...
go vet ./...
go test ./...
```

## Two binaries

- **`cmd/kayra`** — the server binary: `serve`, `reconciler`, `cache
  clean`, `token mint`. Always reads `kayra.yaml` directly. Not
  something a plain end user runs.
- **`cmd/cli`** (`kayra-cli`) — the portable client an end user logs
  in with. Never reads `kayra.yaml` or any local config — see the
  [CLI reference](docs/cli.md).

```bash
go build -o kayra ./cmd/kayra
./kayra --config kayra.yaml serve
# or: export KAYRA_CONFIG_FILE=kayra.yaml && ./kayra serve
# --help works at every level: ./kayra --help, ./kayra cache --help, ...
```

One YAML file covers everything — `app:` (infrapi/lib's shared
`INFRAPI_APP_*` bootstrap config), plus the database backend,
authentication providers and authorization backends. See
[`examples/kayra.yaml`](examples/kayra.yaml) for a fully commented,
runnable copy, and [config](docs/packages/config.md) for the full
reference.

## Bootstrapping the first token

A brand new deployment has no user, group or RBAC object yet — nothing
to log in *against*. `kayra token mint` signs a JWT straight from a
configured local signing key, embedding whatever groups you ask for:

```bash
./kayra --config kayra.yaml token mint --provider self --group sandbox-core-sysadmin
```

That only works if the named provider's authorization backend is
`claims`-typed (the token's own `groups` claim is trusted directly,
never re-checked against a directory — see
[`examples/kayra.yaml`](examples/kayra.yaml)'s `self-claims` entry).
Past bootstrap, real users log in normally (`kayra-cli login`) and this
command is only needed again for a genuine break-glass credential.

## Core concepts

- **RBAC** — `Group`/`Role`/`RoleBinding`, cluster- and
  namespace-scoped, gated by real resolved directory groups (never a
  synced membership list). See
  [RBAC & auth](docs/architecture/rbac-and-auth.md).
- **Stack** — a cluster-wide infrastructure component (e.g. "vault"),
  its own API group. See [Stacks](docs/architecture/stacks.md).
- **Namespace** — *is* the tenant, not two things joined by a name.
  See [Namespaces](docs/architecture/namespaces.md).
- **Subscription** — links a namespace to a stack by name; only
  `kayra reconciler` (a separate process, see
  [Subscriptions & reconciliation](docs/architecture/subscriptions.md))
  ever flips it active.

## Clearing cached entries

Resolved users and provider JWKS keys are cached in the store with a
TTL — a config change (a new `member_regex`, a rotated key) only takes
effect for already-cached entries once cleared or expired:

```bash
./kayra --config kayra.yaml cache clean                                       # everything
./kayra --config kayra.yaml cache clean --scope auth                          # all JWKS caches
./kayra --config kayra.yaml cache clean --scope auth --provider okta          # one provider's JWKS
./kayra --config kayra.yaml cache clean --scope users --authz idm             # one backend's users
./kayra --config kayra.yaml cache clean --scope users --authz idm --user jdoe # one user
```

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
| `internal/catalog` | `Stack`/`Namespace`/`Subscription` + the reconciler |
| `internal/tokenapi` | Personal access token issuance |
| `internal/apiserver` | Wires every package above onto one gin engine |

`cmd/kayra` wires all of it together; `cmd/cli` depends on none of it.

## More

See [the docs](docs/index.md) for the full architecture reference.
