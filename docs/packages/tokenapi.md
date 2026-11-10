---
title: tokenapi
description: Issues personal access tokens, which are opaque rather than JWTs.
weight: 140
---

# tokenapi

```go
import "github.com/infrapi/kayra/internal/tokenapi"
```

Issues personal access tokens: opaque, not JWTs, so their content is never
visible from the etcd record alone — the spec's "Tokens" section.

```go
tokenapi.RegisterRoutes(engine, authenticator.Middleware(), s, keys, &patKey.PublicKey, cfg)
```

`POST /api/v1/tokens` behind `gate` (normally
[`middleware.Authenticator`](middleware.md#authenticator)): the caller must
already be authenticated by any configured provider. Body `{"type": "pat"}`
— `type` defaults to `"pat"` and nothing else is supported today, per the
spec's "for now we only support personal => pat".

```go
{"type": "pat", "token": "pat_<base64url>"}
```

The token is [`crypto.GenerateToken`](crypto.md#pat-records)'s opaque
value; the record behind it
([`crypto.PatRecord`](crypto.md#pat-records): `UserID`, `Authorization`,
`Provider`, `CreatedAt`) is encrypted under `pub` and stored at
`keys.PatToken(crypto.HashToken(token))` — looked up by hash, never by the
token value itself. The PAT always inherits every role of every group its
holder is currently a member of, resolved live at use time by
[`middleware.Authenticator`](middleware.md#authenticator) — never
snapshotted into the record.

The one exception: when the caller's own `ac.Authorization` names a
`claims`-backed `authorizations.<name>` entry (see
[config](config.md#claims-no-directory-at-all)), `cfg` is consulted to
recognize that case, and the record also carries
`SnapshotGroups`/`SnapshotAttributes` — a copy of this same request's
already-resolved `ac.Groups`/`ac.Attributes` — since that backend has
no directory left to re-query later by bare user id alone. Any other
backend leaves both nil and keeps the "always live" behavior above.
