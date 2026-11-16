---
title: discovery
description: Serves Kayra's discovery document, /.well-known/kayra.json — its API domain, built-in groups and endpoints — for infrapi/lib and kayra-cli.
weight: 65
---

# discovery

```go
import "github.com/infrapi/kayra/internal/discovery"
```

Serves Kayra's own discovery document at `GET /.well-known/kayra.json`
(`discovery.Path`), unauthenticated, so its clients configure Kayra's URL
and nothing else:

```json
{
  "domain": "infrapi.io",
  "apis": {
    "system": "/apis/system.infrapi.io/v1",
    "catalog": "/apis/catalog.infrapi.io/v1",
    "authorization": "/apis/authorization.infrapi.io/v1"
  },
  "endpoints": {
    "userinfo": "/oauth2/userinfo",
    "check": "/apis/authorization.infrapi.io/v1/check",
    "jwks": "/oauth2/discovery/keys",
    "apis": "/apis"
  }
}
```

| Field | What it is |
|---|---|
| `domain` | `app.api_domain`: Kayra's built-in groups are `<name>.<domain>` |
| `apis` | each built-in group's path |
| `endpoints.userinfo` | resolves a bearer token to its identity |
| `endpoints.check` | decides whether a caller may act (see [rbac](rbac.md)) |
| `endpoints.jwks` | the public keys of Kayra's self-signed tokens (see [oidc](oidc.md)) |
| `endpoints.apis` | the discovery of every API group, with its resources and short names |

Paths are relative to Kayra's URL, so they hold behind a gateway serving
Kayra on its own host. The document changes only with the configuration:
it is sent with `Cache-Control: public, max-age=300`.

It describes Kayra itself, not the catalog. Only Kayra has a domain: a
registered API is named in full (`compute.infrapi.io`), and `GET /apis`
lists them all.

Its readers:

- [infrapi/lib](https://github.com/infrapi/lib)'s `auth.Client`, which
  finds the check endpoint `RequireAccess` asks there;
- `kayra-cli`, for `auth can-i`'s check endpoint and to tell Kayra's own
  groups from other APIs (see [cli](../cli.md#can-i)).

```go
discovery.Register(engine, discovery.New(apiDomain, discovery.Groups{
	System: catalog.SystemAPI, Catalog: catalog.CatalogAPI, Authorization: rbac.AuthorizationAPI,
}, "/oauth2/userinfo", "/oauth2/discovery/keys", "/apis"))
```

`apiserver.Build` mounts it once the domain is set.
