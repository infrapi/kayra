# CLI

Two binaries (both built on [`urfave/cli/v3`](https://github.com/urfave/cli)),
split by audience:

| Binary | Package | Who it's for | Touches local config? |
|--------|---------|--------------|------------------------|
| `kayra` | [`cmd/kayra`](#kayra-serve-reconciler-cache-token-mint) | whoever runs/operates this Kayra instance | yes — always reads `kayra.yaml` |
| `kayra-cli` | [`cmd/cli`](#kayra-cli-login-context) | any end user, anywhere | never — talks only to a server's own API |

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

```bash
./kayra --config kayra.yaml serve
```

Loads the Kayra YAML config, resolves its `app:` block into
`INFRAPI_APP_*` (via `config.AppConfig.ToVariables` and
`libconfig.NewConfigFromMap`), builds the gin engine, and listens on
`INFRAPI_APP_LISTEN_ADDRESS`.

### reconciler

Runs [`catalog.Reconciler`](architecture/subscriptions.md#reconciler) — the
namespace/subscription/stack reconcile controller — as its **own** process,
deliberately not a goroutine inside `serve`.

```bash
./kayra --config kayra.yaml reconciler
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
why this matters — a single stack `sync_id` bump can fan out into
reconciling every one of its subscribers at once.

A stack with no `mode` of its own otherwise fails
[reconcile](architecture/subscriptions.md#reconcile) forever;
`reconciler.default_mode` gives it one to fall back to instead:

```yaml
reconciler:
  default_mode: trigger # any mode name you use under reconciler.mode — omit
                         # to keep a mode-less stack failing reconcile
```

A stack's own `mode` always wins over this when it has one.

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
./kayra --config kayra.yaml cache clean                              # everything
./kayra --config kayra.yaml cache clean --scope auth                 # all JWKS caches
./kayra --config kayra.yaml cache clean --scope auth --provider okta # one provider's JWKS
./kayra --config kayra.yaml cache clean --scope users --authz idm           # one backend's users
./kayra --config kayra.yaml cache clean --scope users --authz idm --user jdoe # one user
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
./kayra --config kayra.yaml token mint \
  --provider self --group sandbox-core-sysadmin --ttl 1h
```

Only works against a provider whose `authorization:` backend is
`claims`-typed — the whole point of a self-signed bootstrap token is
that its own `groups` claim *is* the trust statement, never re-checked
against a directory (see [config](packages/config.md#claimsauthzconfig)
and `examples/kayra.yaml`'s `self-claims` entry).

| Flag | Default | Meaning |
|------|---------|---------|
| `--provider` | — | required; the `authentifications.<name>` entry naming the signing key |
| `--subject` | `bootstrap` | the token's `sub` claim |
| `--group` | — | a group to embed in the token's `groups` claim; repeatable |
| `--ttl` | `1h` | how long the token is valid for |

## kayra-cli (login, context)

```go
import "github.com/infrapi/kayra/cmd/cli"
```

The portable, end-user Kayra client — hand someone this binary and a
server URL, nothing else. It never reads `kayra.yaml`, has no `--config`
flag, and never needs to know which `authentifications.<name>` a server
configures: every command here only ever talks to that server's own API.

### login

A browser-based OAuth2 flow against a Kayra server you only know the URL
of — the one way to authenticate with this binary.

```bash
./kayra-cli login --server https://kayra.example.com
# oauth2login: opening browser to log in:
#
#   https://kayra.example.com/oauth2/v1/authorize?...
#
# kayra-cli: logged in — saved context "kayra.example.com" to ~/.config/kayra/config (now current)
# kayra-cli: run `kayra-cli context token` to print the bearer token
```

The token itself is never printed — it's already in the context file this
just wrote; read it back with [`context token`](#context) whenever you
actually need it.

`--server`'s own `/oauth2/v1/authorize` resolves which
`authentifications.<name>` to use on your behalf — automatically when the
server configures exactly one `remote.oauth2` provider, or via a one-click
chooser page when it configures several (each option there links straight
to the provider's own login, never through a second confirmation click —
see [oauth2broker](packages/oauth2broker.md)) — and relays that provider's
own public token endpoint/client ID back at the end so this CLI can finish
the PKCE exchange itself, with zero prior knowledge of which provider it
was.

| Flag | Default | Meaning |
|------|---------|---------|
| `--server` | — | required; the Kayra server's base URL |
| `--context-name` | sanitized `--server` host | name to save this login under (see [context](#context)) |
| `--timeout` | `2m` | how long to wait for the browser round trip |

See [oauth2login](packages/oauth2login.md) for how the flow itself works.

### context

Manages `~/.config/kayra/config` — the file `login` writes to on every
successful login ([internal/clicontext](packages/clicontext.md)). Its
shape mirrors `kubectl`'s own `~/.kube/config`: a map of named contexts
(server, token, expiry) plus a `current_context`, so switching back to an
earlier login never requires authenticating again. Override the path with
`$KAYRA_CONTEXT_FILE`.

```bash
./kayra-cli login --server https://kayra.internal
./kayra-cli login --server https://kayra-staging.internal --context-name staging

./kayra-cli context list
# CURRENT  NAME                       SERVER                            EXPIRY
#          kayra.internal           https://kayra.internal          2026-11-03T16:04:05+01:00
# *        staging                    https://kayra-staging.internal  2026-11-03T17:04:05+01:00

./kayra-cli context use kayra.internal  # switch back without logging in again
./kayra-cli context current               # show the active context's details
./kayra-cli context token                 # print the active context's bearer token
./kayra-cli context token staging         # print a specific context's token
./kayra-cli context delete staging        # drop a saved login
```

| Subcommand | Args | Meaning |
|------------|------|---------|
| `list` | — | list saved contexts, marking the current one with `*` |
| `current` | — | print the current context's name, server, expiry |
| `use` | `<name>` | switch the current context |
| `delete` | `<name>` | remove a saved context |
| `token` | `[name]` | print a context's bearer token (defaults to current) |
