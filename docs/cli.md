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
kayra-cli login --server https://kayra.example.com
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

The server's own `app.api_domain` is relayed the same way and saved into
the context alongside the token — `auth can-i` and the
[generic verbs](#kayra-cli-get-create-update-patch-delete) read it back
from there, so they never have to guess `example.com` for a server that
configured something else. A context saved before this existed (or one
created by hand) simply has none, same fallback as before.

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
kayra-cli login --server https://kayra.internal
kayra-cli login --server https://kayra-staging.internal --context-name staging

kayra-cli context list
# CURRENT  NAME                       SERVER                            EXPIRY
#          kayra.internal           https://kayra.internal          2026-11-03T16:04:05+01:00
# *        staging                    https://kayra-staging.internal  2026-11-03T17:04:05+01:00

# save an existing token (e.g. a `kayra token mint` bootstrap token) without logging in
kayra-cli context set bootstrap --server http://localhost:8080 --token "$TOKEN"

kayra-cli context use kayra.internal  # switch back without logging in again
kayra-cli context current               # show the active context's details
kayra-cli context token                 # print the active context's bearer token
kayra-cli context token staging         # print a specific context's token
kayra-cli context delete staging        # drop a saved login
```

| Subcommand | Args | Meaning |
|------------|------|---------|
| `list` | — | list saved contexts, marking the current one with `*` |
| `current` | — | print the current context's name, server, expiry |
| `set` | `<name>` | save `--token` for `--server` (optionally `--api-domain`) as a context and make it current — no login flow |
| `use` | `<name>` | switch the current context |
| `delete` | `<name>` | remove a saved context |
| `token` | `[name]` | print a context's bearer token (defaults to current) |

### auth (can-i, whoami)

Two checks that ask a server about the current login itself, rather
than managing it.

#### can-i

Mirrors `kubectl auth can-i`: asks the server's own
[`/apis/authorization.<domain>/v1/check`](architecture/rbac-and-auth.md#authorizing-other-apps-requests)
whether the current context's already-authenticated identity is
granted `<verb>` on `<resource>` for `--api` — the decision is always
the server's, never asserted locally.

```bash
kayra-cli auth can-i get pods --api compute.example.com --namespace core
# yes

kayra-cli auth can-i delete pods --api compute.example.com --namespace core
# no
# kayra-cli: your role does not grant this action
```

Prints `yes`/`no` to stdout and exits `0`/`1` accordingly — scriptable
exactly like `kubectl auth can-i`. A denial's reason (when the server
gives one) goes to stderr, never mixed into stdout.

**This only ever tests `rbac.Authorize`** — namespace-scoped
`Group`/`Role`/`RoleBinding` objects, the mechanism *other* apps built
on infrapi/lib use to authorize their own API. None of Kayra's own
management-plane routes are decided by it:

| Asking about... | Actually gated by |
|---|---|
| `authorization.<domain>`'s `groups`/`roles`/`rolebindings` | cluster RBAC (`CanManageNamespaceRBAC`) — a different, cluster-scoped `Group`/`Role`/`RoleBinding` set |
| `subscription.<domain>`'s `subscriptions` | cluster RBAC (`CanManageNamespaceRBAC`), same as above |
| `authorization.<domain>`'s `clustergroups`/`clusterroles`/`clusterrolebindings` | the sysadmin group alone (`SysadminGate`) — no `Rule` consulted at all |
| `catalog.<domain>`'s `apiregistrations` | `SysadminGate` alone |
| `apps.<domain>`'s `namespaces` | `SysadminGate` alone |

Asking about one of these still gets a real, truthful answer — "does
a stored `Rule` grant this" — just not necessarily the answer to "will
the real endpoint let me." `can-i` prints a warning to stderr whenever
`--api`/the verb's resource names one of them, so a "yes" or "no"
here is never mistaken for the real decision. For anything
`SysadminGate`-gated, compare [`whoami`](#whoami)'s `groups` against
`sysadmin.groups` in the server's own config yourself — neither this
command nor the server exposes that comparison any other way.

| Flag | Default | Meaning |
|------|---------|---------|
| `--api` | — | required; the API group being asked about, e.g. `compute.example.com` — never Kayra's own `authorization.<domain>` |
| `--namespace` | — | required; the namespace to check against |
| `--api-domain` | everything in `--api` past its first label, else the current context's own saved `api_domain` (see `login`), else `example.com` | this deployment's own `app.api_domain` — only used to reach `/apis/authorization.<domain>/v1/check` itself; `--api compute.example.com` alone is enough, since the check endpoint lives on that same domain |
| `--context` | current context | saved context to use instead |

#### whoami

Prints exactly what the server's own `GET /oauth2/userinfo` returns
for the current login — `sub`, `provider`, `authorization`, `groups`,
plus whatever `authorizations.<name>` attributes (`email`, `name`,
...) that backend resolved. This is the same identity any `can-i`
decision, or any other RBAC check against this token, is actually made
against.

```bash
kayra-cli auth whoami
# authorization:  idm
# email:           jdoe@example.com
# groups:          sandbox-core-sysadmin, sandbox-thetenant-admins
# name:            John Doe
# provider:        self
# sub:             jdoe
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--context` | current context | saved context to use instead |

## kayra-cli (get, create, update, patch, delete)

kubectl-style top-level verbs — a thin, generic REST client against
*any* app's own API, following the exact URN/route convention Kayra's
own resources use (see
[RBAC & auth](architecture/rbac-and-auth.md#authorizing-other-apps-requests)):

```
{server}/apis/<api>.<domain>/v1/namespaces/<namespace>/<resource>[/<name>]   # -n given: namespace-scoped
{server}/apis/<api>.<domain>/v1/<resource>[/<name>]                          # -n omitted: cluster-scoped
```

authenticated with the current context's own bearer token. Kayra
itself never implements any of these APIs (see
[API registrations](architecture/api-registrations.md)) — this is just
the one HTTP convention every app following it shares, so one verb set
works against all of them, Kayra's own resources included — both
namespace-scoped (`subscription`'s subscriptions, `authorization`'s
per-namespace groups/roles/rolebindings) and cluster-scoped
(`catalog`'s `apiregistrations`, `authorization`'s
`clustergroups`/`clusterroles`/`clusterrolebindings`):

Each example's `curl` tab is the exact request the verb sends, against
`http://localhost:8080` with `app.api_domain` left at `example.com` —
take the token from the current context with
`TOKEN=$(kayra-cli context token)`.

=== "kayra-cli"

    ```bash
    # namespace-scoped: -n selects .../namespaces/<ns>/<resource>
    kayra-cli get subscription -n thetenant subscriptions
    # []
    kayra-cli create subscription -n thetenant subscriptions -d '{"api": "vault.example.com"}'
    # {"api": "vault.example.com", "active": false, "state": "init", ...}
    kayra-cli get subscription -n thetenant subscriptions vault.example.com
    kayra-cli update subscription -n thetenant subscriptions vault.example.com/sync -d '{}'
    kayra-cli delete subscription -n thetenant subscriptions vault.example.com

    # cluster-scoped: no -n, addresses .../<resource> directly
    kayra-cli create catalog apiregistrations -d '{"name": "vault.example.com", "short_name": "vault", "owner": "sre"}'
    kayra-cli get catalog apiregistrations
    kayra-cli create authorization clustergroups -d '{"name": "g", "metadata": {...}, "groups": [...]}'
    ```

=== "curl"

    ```bash
    # namespace-scoped: -n selects .../namespaces/<ns>/<resource>
    curl -s http://localhost:8080/apis/subscription.example.com/v1/namespaces/thetenant/subscriptions \
      -H "Authorization: Bearer $TOKEN"
    # []
    curl -s -X POST http://localhost:8080/apis/subscription.example.com/v1/namespaces/thetenant/subscriptions \
      -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -d '{"api": "vault.example.com"}'
    # {"api": "vault.example.com", "active": false, "state": "init", ...}
    curl -s http://localhost:8080/apis/subscription.example.com/v1/namespaces/thetenant/subscriptions/vault.example.com \
      -H "Authorization: Bearer $TOKEN"
    curl -s -X PUT http://localhost:8080/apis/subscription.example.com/v1/namespaces/thetenant/subscriptions/vault.example.com/sync \
      -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -d '{}'
    curl -s -X DELETE http://localhost:8080/apis/subscription.example.com/v1/namespaces/thetenant/subscriptions/vault.example.com \
      -H "Authorization: Bearer $TOKEN"

    # cluster-scoped: no -n, addresses .../<resource> directly
    curl -s -X POST http://localhost:8080/apis/catalog.example.com/v1/apiregistrations \
      -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -d '{"name": "vault.example.com", "short_name": "vault", "owner": "sre"}'
    curl -s http://localhost:8080/apis/catalog.example.com/v1/apiregistrations \
      -H "Authorization: Bearer $TOKEN"
    curl -s -X POST http://localhost:8080/apis/authorization.example.com/v1/clustergroups \
      -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -d '{"name": "g", "metadata": {...}, "groups": [...]}'
    ```

`get` maps to `GET` either way — no trailing `<name>` lists the whole
collection (`.../<resource>`), a `<name>` fetches that one item
(`.../<resource>/<name>`), exactly like `kubectl get` itself (and
exactly how Kayra's own collection vs. item routes already distinguish
the two) — there is no separate `list` verb. `create` is `POST`,
`update` is `PUT`, `patch` is `PATCH`, `delete` is `DELETE` —
`update`/`patch`/`delete` all require `<name>`; `create`/`update`/
`patch` all require a body. A sub-resource action is just part of
`<name>` (`vault/sync` above — "PATCH .../vm/:id/reboot" in the
general case, see
[RBAC & auth](architecture/rbac-and-auth.md#authorizing-other-apps-requests)),
never a separate argument.

The response body is printed pretty-printed as-is — this never
interprets or re-shapes it, since it has no idea what shape any given
`<api>`'s own resource actually is. A non-2xx response still prints
the body (typically the same RFC 9457 problem-detail shape
[`httpapi.Fail`](packages/httpapi.md) uses) and exits `1`.

| Flag | Default | Meaning |
|------|---------|---------|
| `--namespace`, `-n` | — | the namespace to address — omit for a cluster-scoped resource |
| `--api-domain` | everything in `<api>` past its first label, else the current context's own saved `api_domain` (see `login`), else `example.com` | same resolution as `auth can-i`'s flag of the same name |
| `--data`, `-d` | — | request body, as a raw JSON string (`create`/`update`/`patch` only) |
| `--filename`, `-f` | — | request body, read from a file — `-` for stdin (`create`/`update`/`patch` only) |
| `--context` | current context | saved context to use instead |
