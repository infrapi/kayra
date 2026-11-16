---
title: CLI
description: Reference for the kayra server binary; the end-user client is infrapi-cli.
weight: 40
---

# CLI

`kayra` is the server binary, built on
[`urfave/cli/v3`](https://github.com/urfave/cli), for whoever runs and
operates a Kayra instance: it always reads `kayra.yaml`.

The end user's client is a separate binary, in its own repository:
[`infrapi-cli`](https://github.com/infrapi/cli) logs in to a Kayra server
and calls its API (`login`, `context`, `auth can-i`, `apis`, `get`,
`create`, `update`, `patch`, `delete`), knowing nothing but the server's
URL. See [its docs](https://infrapi.github.io/cli/).

## kayra (serve, reconciler, cache, token mint)

```go
import "github.com/infrapi/kayra/cmd/kayra"
```

`--config` (default `kayra.yaml`, or `$KAYRA_CONFIG_FILE`) is a global
flag: it works before or after the subcommand, and never needs repeating
once set via the environment variable. Every command under this binary
reads it — this is the app-management binary, not something a plain end
user would ever run.

### serve

Runs the HTTP API — every route [apiserver.Build](packages/apiserver.md)
wires up.

> [!TIP]
> The commands below use the `kayra` binary: [install it](getting-started.md#1-install).

```bash
kayra --config kayra.yaml serve
```

Loads the Kayra YAML config, resolves its `app:` block into
`INFRAPI_APP_*` (via `config.AppConfig.ToVariables` and
`libconfig.NewConfigFromMap`), builds the gin engine, and listens on
`INFRAPI_APP_LISTEN_ADDRESS`.

### reconciler

Runs [`catalog.Reconciler`](architecture/subscriptions.md#reconciler) — the
namespace/subscription/api registration reconcile controller — as its
**own** process,
deliberately not a goroutine inside `serve`.

```bash
kayra --config kayra.yaml reconciler
```

Stops cleanly on `SIGINT`/`SIGTERM`: the signal cancels the context
`Reconciler.Run` is watching, so it finishes its current pass and returns
instead of being killed mid-write.

How many reconcile/activate operations run at once is capped by
`reconciler.max_concurrent_reconciles` in `kayra.yaml` (default `30` —
`catalog.DefaultMaxConcurrentReconciles`):

```yaml
reconciler:
  max_concurrent_reconciles: 30
```

See [Subscriptions & reconciliation](architecture/subscriptions.md#reconciler) for
why this matters — a single api registration `sync_id` bump can fan out into
reconciling every one of its subscribers at once.

An api registration with no `mode` of its own otherwise fails
[reconcile](architecture/subscriptions.md#reconcile) forever;
`reconciler.default_mode` gives it one to fall back to instead:

```yaml
reconciler:
  default_mode: trigger # any mode name you use under reconciler.mode — omit
                         # to keep a mode-less api registration failing reconcile
```

An api registration's own `mode` always wins over this when it has one.

What a mode actually *does* is itself configurable:
`reconciler.mode.<mode>` is an HTTP step pipeline — see
[Subscriptions & reconciliation](architecture/subscriptions.md#http-step-pipeline)
for the full reference, and `examples/kayra.yaml` for a worked example.
Without it, `reconcile` keeps its original log-only placeholder for that
mode.

### cache clean

Clears cached entries directly in the configured store — see
[authz](packages/authz.md#cached) and [oidc](packages/oidc.md#manager) for
what gets cached and why.

```bash
kayra --config kayra.yaml cache clean                              # everything
kayra --config kayra.yaml cache clean --scope auth                 # all JWKS caches
kayra --config kayra.yaml cache clean --scope auth --provider okta # one provider's JWKS
kayra --config kayra.yaml cache clean --scope users --authz idm           # one backend's users
kayra --config kayra.yaml cache clean --scope users --authz idm --user jdoe # one user
```

| Flag | Applies to | Meaning |
|------|-----------|---------|
| `--scope` | always | `all` (default), `users` or `auth` |
| `--authz` | `users` | limit to one `authorizations.<name>` backend |
| `--user` | `users` | limit to one user id (requires `--authz`) |
| `--provider` | `auth` | limit to one `authentifications.<name>` provider |

### token mint

Signs a JWT directly from a configured `authentifications.<name>.local`
key — no HTTP round trip, no prior session. This is the one way to get
a first bearer token into a brand new deployment: before any user,
group or RBAC object exists, there's nothing to log in *against*.

```bash
kayra --config kayra.yaml token mint \
  --provider self --group sandbox-core-sysadmin --ttl 1h
```

Only works against a provider whose `authorization:` backend is
`claims`-typed — the whole point of a self-signed bootstrap token is
that its own `groups` claim *is* the trust statement, never re-checked
against a directory (see [config](packages/config.md#claims-no-directory-at-all)
and `examples/kayra.yaml`'s `self-claims` entry).

| Flag | Default | Meaning |
|------|---------|---------|
| `--provider` | — | required; the `authentifications.<name>` entry naming the signing key |
| `--subject` | `bootstrap` | the token's `sub` claim |
| `--group` | — | a group to embed in the token's `groups` claim; repeatable |
| `--ttl` | `1h` | how long the token is valid for |
