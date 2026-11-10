---
title: config
description: Loads and validates the Kayra YAML configuration file.
weight: 50
---

# config

```go
import "github.com/infrapi/kayra/internal/config"
```

Loads and validates the Kayra YAML configuration file: the shared
`app:` bootstrap block, the storage backend, authentication providers
and authorization backends. Distinct from
[infrapi/lib's own `pkg/config`](https://infrapi.github.io/lib/packages/config/),
which resolves those same `INFRAPI_APP_*` keys once flattened — Kayra
authors them here in YAML instead of a separate dotenv file, and hands
them off via `libconfig.NewConfigFromMap`.

## Loading

```go
cfg, err := config.Load("kayra.yaml")
```

`Load` reads the file, unmarshals it as YAML, and runs `cfg.Validate()`
before returning — a bad config fails at startup, never partway through a
request.

```go
type Config struct {
	App               AppConfig
	Database          map[string]DatabaseBackend
	Authentifications map[string]AuthProvider
	Authorizations    map[string]AuthorizationBackend
	Tokens            TokensConfig
	Reconciler        ReconcilerConfig
}
```

`Database`, `Authentifications` and `Authorizations` are all maps so the
YAML can name entries however it likes (`main`, `dev`, `idm`, ...); `Load`
only ever cares about the values.

## App

```go
type AppConfig struct {
	Name, FQDN, URL                    string
	Platform, Region, Location         string
	ListenType, ListenAddress          string
}
```

```yaml
app:
  name: "auth"
  fqdn: "localhost.local"
  url: "http://localhost:8080"
  platform: "sandbox"
  region: "eu-west-1"
  location: "dc1"
  listen_type: "tcp"
  listen_address: "0.0.0.0:8080"
```

`AppConfig.ToVariables()` flattens this into the exact `INFRAPI_APP_NAME`/
`_PLATFORM`/`_REGION`/`_LOCATION`/`_FQDN`/`_URL`/`_LISTEN_TYPE`/
`_LISTEN_ADDRESS` keys a dotenv file would otherwise have provided:

```go
appVars := libconfig.NewConfigFromMap(cfg.App.ToVariables(), "kayra.yaml")
appCfg, err := appVars.GetAppConfig()
```

`GetAppConfig` is where the real validation happens — required fields
(`name`, `platform`, `region`, `location`, `url`), `oneof` for
platform/region/location, `fqdn`/`http_url`/`hostname_port` format checks
— owned entirely by infrapi/lib's own `DefaultConfig`, not duplicated
here. A field left empty in `app:` is passed through as an empty string,
which `GetString` treats the same as an absent dotenv key: it falls back
to that key's own default (`fqdn`, `listen_type`, `listen_address`,
`log_level`, `log_format`, the CORS keys) when it has one, or fails with
a clear error naming the missing key when it doesn't.

## Database

Exactly one entry is required, and exactly one of its two backends:

```go
type DatabaseBackend struct {
	Etcd  *EtcdConfig  // real etcd cluster
	Local *LocalConfig // a directory of files, for dev/test
}
```

`cfg.ActiveDatabase()` returns that single entry's name and backend —
[`store.New`](store.md) is built directly from it.

```yaml
database:
  main:
    etcd:
      host: ["https://etcd0:2379", "https://etcd1:2379"]
      prefix: "/kayra"
      timeout: 30
      tls:
        verify: true
        cacert: /path/cacert.pem
        key: /path/client-key.pem
        cert: /path/client-cert.pem
```

```yaml
database:
  dev:
    local:
      path: /tmp/kayra-db
```

## Authorizations

At least one entry is required; each is exactly one of `ldap`, `local`
or `claims`. `ldap` describes a real directory
([`authz.LDAPAuthorizer`](authz.md)): host/port/bind credentials, TLS,
retry codes, and how a user's id and groups map onto LDAP attributes —
`user.groups.member_regex` is mandatory and must compile. `local`
points at a YAML fixture ([`authz.DevLocalAuthorizer`](authz.md))
standing in for that same directory in dev/test, with the same optional
`member_regex` filtering.

### Claims: no directory at all

`claims` resolves a caller's groups and attributes straight out of
their own already-verified token claims or userinfo response — for a
provider whose token/userinfo already carries real group membership
(Okta's own `MemberOf`, say), with no `ldap`/`local` lookup at all:

```yaml
authorizations:
  okta:
    claims:
      from: userinfo_endpoint   # or "token" — same vocabulary as remote.user_id.from
      groups_field: MemberOf    # a JSON array field; each element becomes one resolved group
      groups_filter: ""         # optional regex, same semantics as ldap.user.groups.member_regex
      user_attributes:          # local name -> claims/userinfo field, same shape as ldap.user.user_attributes
        email: email
        name: name
        employee_id: employeeNumber
```

Given this real Okta userinfo response:

```json
{
  "sub": "00u2u0ebcbkQyFOBz0i7",
  "email": "me@ahmet2mir.eu",
  "employeeNumber": "W110441",
  "MemberOf": ["sandbox-core-sysadmin", "sandbox-sre-sysadmin", "app-netbox-user"]
}
```

that config resolves `Groups: ["sandbox-core-sysadmin", "sandbox-sre-sysadmin", "app-netbox-user"]`
(no `groups_filter` set, so every element passes through as-is — unlike
a raw LDAP `memberOf` value, Okta's own group claim is typically
already a plain name, not a DN needing extraction) and
`Attributes: {"email": "...", "employee_id": "W110441"}`.

`from`/`groups_field` mirror `authentifications.<name>.remote.user_id`'s
own `from`/`field` exactly (see [authn](authn.md)) — the same two
sources, just applied to a list instead of a scalar. No second network
call is made: when `from: userinfo_endpoint`, this reuses the exact
response already fetched to resolve the user id.

A `claims` backend cannot back a username/password login (there is no
username/password to check — only an already-issued token) and cannot
be re-resolved later from a bare user id alone (there
is no live session left to re-query). [Personal access tokens](../architecture/rbac-and-auth.md)
cope with that by snapshotting `Groups`/`Attributes` into the token
record at creation time instead of resolving them live on every use —
the one case where a PAT's roles don't track a later change in group
membership until the token is regenerated.

`from: userinfo_endpoint` only makes sense for a `claims` backend
referenced by a `remote` `authentifications.<name>` entry: resolving it
means calling that provider's own userinfo endpoint, and a `local`
(self-signed) provider has no provider session to call back into at
all. [Validate](#validate) rejects that combination outright — a local
provider wanting claims-based authorization must use `from: token`
instead, reading straight out of the self-signed token's own claims
(e.g. whatever `groups` claim [`crypto.MintSelfJWT`](crypto.md#self-issued-jwts)
already embeds).

## Authentifications

At least one entry is required, each naming which `authorizations.<name>`
it resolves users against, and exactly one of:

- `remote` — an OIDC-discovery-backed provider (Okta, GitLab, a console,
  ...): `url` to the discovery document, and `user_id` saying where the
  user id comes from (`from: token` reads a claim, `from:
  userinfo_endpoint` calls the provider's userinfo endpoint), optionally
  narrowed by a regex `filter`. Two more fields are optional:
  - `proxy` — an HTTP(S) proxy URL every outbound call *this* provider
    makes (discovery, JWKS, userinfo, and `oauth2`'s own authorize/token
    calls below) is routed through, via
    [`oidc.ClientFor`](oidc.md#clientfor) — independently of any other
    provider, and independently of the process-wide
    `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` env vars Go's default
    transport already honors when this is unset. [Validate](#validate)
    rejects an unparseable one.
  - `oauth2` — `client_id` (required if set) and `scopes` (defaults to
    `oauth2login.DefaultScopes`: `openid`, `profile`, `email`) for
    [`kayra-cli login`](../cli.md#login): a real browser-based OAuth2
    Authorization Code + PKCE flow, saving the provider's own token into
    a context. The CLI's browser opens at *this Kayra instance's
    own* `/oauth2/v1/authorize`, never this provider's directly — most
    enterprise IdPs (Okta included) will never allowlist a CLI's
    loopback redirect_uri — which relays the real flow on to
    `authorization_endpoint`/`token_endpoint` and back (see
    [oauth2broker](oauth2broker.md)/[oauth2login](oauth2login.md)). A
    public client throughout (PKCE replaces the need for a
    `client_secret`, and Kayra's relay never introduces one), so
    there is nothing else to configure here — just this same
    `client_id` the provider already knows about for a native/public
    app.
- `local` — one or more RSA signing keys this instance trusts for
  self-issued tokens (the `self` provider the spec's bootstrap flow uses):
  `kid`, `algorithm`, whether it can `issuer` (sign, not just verify), and
  the PEM-encoded `secret`.

```yaml
authentifications:
  okta:
    authorization: idm
    remote:
      enabled: true
      url: https://example.okta.com/.well-known/openid-configuration
      user_id: {from: token, field: sub, filter: '^([^@]+)@'}
      proxy: http://proxy.corp.example:8080
      oauth2:
        client_id: "<this CLI's client_id in Okta's own app registration>"
        scopes: [openid, profile, email]

  self:
    authorization: idm
    local:
      - {enabled: true, algorithm: RS512, issuer: true, kid: "k1", secret: "-----BEGIN PRIVATE KEY-----..."}
```

## Tokens

```go
type TokensConfig struct {
	Pat PatConfig
}

type PatConfig struct {
	PrivateKeyPath string // empty: generate once, persist in the store
	PublicKeyPath  string
}
```

See [crypto](crypto.md#pat-keypair).

## Sysadmin

```go
type SysadminConfig struct {
	Groups []string
}
```

```yaml
sysadmin:
  groups:
    - sandbox-core-sysadmin
    - sandbox-platform-admins
```

The group(s) [`middleware.SysadminGate`](middleware.md#sysadmingate)
requires a caller's resolved groups to intersect, to reach the cluster
bootstrap endpoints. Authored directly here as real LDAP/IdP group names
— never derived from a template the operator has no way to override.
Left empty (the default), `SysadminGate` falls back to a single group,
`middleware.SysadminGroupFor(platform)` (`"<platform>-core-sysadmin"`).

## Reconciler

```go
type ReconcilerConfig struct {
	MaxConcurrentReconciles int                        // <= 0 (the typical case): catalog.DefaultMaxConcurrentReconciles
	DefaultMode             string                     // free-form mode name — "" keeps a mode-less api registration failing reconcile
	Mode                    map[string][]ReconcileStep // the HTTP step pipeline reconcile runs for a given mode name
	GatewayURL              string                     // where every registered api is reachable, as <gateway_url>/apis/<api>/...
}
```

```yaml
reconciler:
  max_concurrent_reconciles: 30
  default_mode: trigger
  gateway_url: https://api.example.com
```

`gateway_url` is where the reconciler fetches each registered api's OpenAPI
spec, from `<gateway_url>/apis/<api>/-/openapi.json`. The spec is
mandatory: with `gateway_url` unset, no sync can complete. See
[API registrations](../architecture/api-registrations.md#openapi-spec).

Caps `kayra reconciler`'s goroutine pool, and gives `reconcile` a mode to
fall back to for an api registration with none of its own — see
[Subscriptions & reconciliation](../architecture/subscriptions.md#concurrency)
and [#reconcile](../architecture/subscriptions.md#reconcile).

### Mode: the HTTP step pipeline

```go
type ReconcileStep struct {
	Method   string
	Endpoint string                 // Go text/template, see below
	Data     map[string]any         // every string leaf templated, however deeply nested; JSON-encoded as the request body
	Headers  map[string]HeaderValue // each value templated
	Timeout  string                 // Go duration string, e.g. "3600s"
	Async    bool                   // default false
	Outputs  map[string]string      // name -> dot path into the JSON response body
	Wait     []WaitCondition        // poll this step's own call until a condition resolves (ignored if Async)
}

type HeaderValue struct {
	Raw         string // plain scalar form: "Content-Type: application/json"
	Type, Value string // {type, value} form: {type: Bearer, value: "tok"} -> "Bearer tok"
}

type WaitCondition struct {
	Key       string   // dot path into the response body, e.g. ".status"
	Successes []string // Key's value landing here resolves the step done
	Failures  []string // Key's value landing here fails the step immediately
}
```

`Mode` is keyed by mode name — `"api"`/`"trigger"` in the examples here,
but any name works, since there's no fixed enum of valid modes, only
`ApiRegistration.Mode`/`DefaultMode` ever being empty is a problem (see
[Reconcile](../architecture/subscriptions.md#reconcile)). Each entry is
the list of calls `reconcile` runs for real once configured —
see [Subscriptions & reconciliation](../architecture/subscriptions.md#http-step-pipeline)
for the full templating/async/outputs/wait reference, and
`examples/kayra.yaml` for a complete worked example.

## Validate

`Validate()` (called automatically by `Load`) checks structural invariants
the YAML schema alone can't express: exactly one backend chosen per union
field (`database.*`, `authorizations.*.{ldap,local,claims}`,
`authentifications.*.{remote,local}`), every `authentifications.*.authorization`
names a real `authorizations` entry (and, when that entry is `claims`
with `from: userinfo_endpoint`, that the referencing provider is
`remote` — see [Claims](#claims-no-directory-at-all)), every `member_regex` compiles,
every `remote.proxy` parses as a URL, every `remote.oauth2` sets
`client_id`, `reconciler.max_concurrent_reconciles` isn't negative, and every
`reconciler.mode.<name>` step has a recognized `method`, a non-empty
`endpoint`, a parseable `timeout`, and a non-empty `key` on each `wait`
entry. Call it directly after hand-building a `Config` in tests.

A full, runnable example lives at `examples/kayra.yaml`.
