---
title: oidc
description: Fetches and caches OIDC discovery documents and JWKS, and serves Kayra's own discovery endpoints.
weight: 110
---

# oidc

```go
import "github.com/infrapi/kayra/internal/oidc"
```

Fetches and caches OIDC discovery documents and JWKS key sets for every
remote `authentifications.<name>` provider, and serves Kayra's own
aggregated discovery/JWKS endpoints — the identity every other provider's
clients can, in principle, point back at Kayra itself for.

## Manager

```go
manager, err := oidc.NewManager(s, keys, cfg)
```

Loads every provider's `local:` signing keys up front
([crypto.LoadSigningKeys](crypto.md#local-signing-keys)) and owns the JWKS
cache for every `remote:` provider.

```go
manager.LocalKeys(provider)       // []crypto.SigningKey for a local: provider
manager.KeysFor(provider)         // []JWK — cached if remote, decoded if local
manager.RefreshRemote(provider)   // re-fetch discovery + JWKS, replace the cache
manager.AllKeys()                 // every enabled provider's keys, aggregated
manager.FindKey(kid)              // locate (provider, JWK) by kid, across every provider
```

`FindKey` checks local providers first (no I/O), then every remote
provider's **cache**, and only refreshes a remote provider's JWKS (once,
each) if no cache held the `kid` — the spec's "absent from cache ->
refresh, otherwise don't" rule. [authn.Verify](authn.md) is `FindKey`'s one
caller.

Cached JWKS live at `keys.AuthCache(provider)` in the store — see
[`kayra cache clean --scope auth`](../cli.md#cache-clean).

## JWK

```go
type JWK struct {
	Kty, Kid, Use, Alg string
	N, E               string // base64url, RSA only
	InfraPIAuthProvider string // which authentifications.<name> this key belongs to
}

pub, err := jwk.PublicKey()              // decode n/e into *rsa.PublicKey
jwk := oidc.NewJWK(provider, kid, alg, pub) // encode the other way
```

`InfraPIAuthProvider` is the spec's extension field tagging every key (both
fetched and self-issued) with the provider it belongs to, so
`/oauth2/discovery/keys`'s aggregated set stays attributable.

## Discovery/JWKS fetch

```go
doc, err := oidc.FetchDiscovery(url, proxy)           // GET .../.well-known/openid-configuration
keys, err := oidc.FetchJWKS(doc.JWKSURI, proxy)       // GET the jwks_uri
info, err := oidc.FetchUserinfo(url, token, proxy)    // POST with Authorization: Bearer
```

`DiscoveryDoc` also carries `AuthorizationEndpoint`/`TokenEndpoint` —
unused by anything in this package itself, but what
[oauth2login](oauth2login.md) builds its own Authorization Code + PKCE
flow against.

`proxy` is a provider's own `authentifications.<name>.remote.proxy`
(empty string for none) — every call here goes through
[`ClientFor(proxy)`](#clientfor), so each provider's outbound traffic is
routed independently. A 10-second timeout either way — these calls are
small and infrequent (results are cached), so no retry/backoff machinery.

## ClientFor

```go
client, err := oidc.ClientFor(proxy)
```

Returns the `*http.Client` every outbound call for one provider should
use: a single shared, env-proxy-aware client (`http.DefaultTransport`,
which already honors `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`) when `proxy`
is empty, or a client pinned to that exact proxy URL otherwise. Also
used by [oauth2login.Login](oauth2login.md) for its own token-exchange
call, so a provider's `remote.proxy` applies there too.

## Kayra's own endpoints

```go
oidc.RegisterRoutes(engine, manager, baseURL)
```

Mounts `GET /.well-known/openid-configuration` (`issuer`, `jwks_uri`,
`userinfo_endpoint` all built from `baseURL`) and `GET
/oauth2/discovery/keys` (`manager.AllKeys()`), unauthenticated — this *is*
the identity document, so it can't itself require already being
authenticated.
