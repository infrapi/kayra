---
title: apiserver
description: The wiring layer that imports every other package and builds the gin engine kayra serve runs.
weight: 10
---

# apiserver

```go
import "github.com/infrapi/kayra/internal/apiserver"
```

The one thin wiring/transport layer that imports every other package and
builds the single gin engine `kayra serve` runs — so `main` only has to
call `Build` once.

```go
engine, err := apiserver.Build(appCfg, cfg)
// appCfg: *libconfig.AppConfig (infrapi/lib's INFRAPI_APP_* config)
// cfg:    *config.Config        (Kayra's own YAML config)
```

In order:

1. `gin.EnableJsonDecoderDisallowUnknownFields()` — posting a
   `Role`-shaped body to a `Group` endpoint (or any mismatched resource)
   fails loudly instead of silently dropping fields it doesn't have.
2. Opens the [store](store.md) from `cfg.ActiveDatabase()`.
3. Builds the [oidc.Manager](oidc.md#manager), one
   [authz.Cached](authz.md#cached) per `authorizations.<name>`, and the
   [PAT keypair](crypto.md#pat-keypair).
4. Builds [`middleware.Authenticator`](middleware.md#authenticator) and
   [`middleware.SysadminGate`](middleware.md#sysadmingate) (wrapping that
   same `Authenticator`, plus `cfg.Sysadmin.Groups` — falling back to
   `middleware.SysadminGroupFor(appCfg.AppPlatform)` when left empty).
5. Mounts, via [`infrapi/lib`'s `pkg/server`](https://infrapi.github.io/lib/packages/server/):
   the discovery/metrics/docs endpoints, `oidc`'s own routes, `GET`/`POST
   /oauth2/userinfo` (both, per OIDC Core §5.3.1: GET MUST be supported,
   POST MAY be — most real providers accept either),
   [oauth2broker](oauth2broker.md)'s three routes (`kayra-cli login`'s
   own browser relay), then
   [rbac](rbac.md)'s cluster and namespace routes,
   the [catalog](../architecture/overview.md#catalog)'s
   cluster/namespace/namespace-collection routes, and
   [tokenapi](tokenapi.md)'s route.

[`catalog.Reconciler`](../architecture/subscriptions.md#reconciler) deliberately
does **not** run here: it's its own `kayra reconciler` process (see
[the CLI reference](../cli.md#reconciler)), not a goroutine mixed into the API
server.
