---
title: httpapi
description: RFC 9457 error responses for Kayra's own middlewares, and the request's context, errors and type conversions for the handlers generated from its contracts.
weight: 70
---

# httpapi

```go
import "github.com/infrapi/kayra/internal/httpapi"
```

Centralises how every Kayra handler turns an error into an HTTP response,
using [infrapi/lib's `pkg/errors`](https://infrapi.github.io/lib/packages/errors/)
RFC 9457 problem-detail payload.

```go
httpapi.Fail(c, liberrors.New(http.StatusNotFound, "catalog.GetApiRegistration", "api registration %q not found", name))
```

Writes `err` as the response body (`liberrors.MediaType` content type) and
aborts the gin context, so no further handler in the chain runs — a
middleware refusing a request included. This is what Kayra's own gin middlewares ([middleware](middleware.md),
the routes outside the contracts) call on failure. The handlers generated
from the [contracts](../development.md#contracts) return an error instead,
which the generated `Register` answers with infrapi/lib's
`server.AbortError`: the same problem document, so every error response
across the whole API has the identical shape, its `solution` included.

## Context and conversion

The generated `Handlers` get the request's context only. What they still
need of the request travels in it:

```go
routes := engine.Group("", httpapi.WithRequest, authenticator.Middleware())

req := httpapi.RequestOf(ctx)          // Method, Path, Params, ClientIP, UserAgent, Header
req.Header.Set("Retry-After", "2")     // the response's header, set before returning
```

- **`WithRequest`** is the middleware in front of a generated `Register`: it
  puts a `Request` in the request's context, its method and path (what
  [`rbac.AuthorizeClusterRequest`](rbac.md#authorizeclusterrequest) decides
  on), its route's parameters, the client's address and agent (the audit's),
  and the response's header. `RequestOf` gives an empty one outside a
  request, a test calling a method directly.
- **`Err(e *liberrors.Error) error`** is `e` as an `error`, `nil` when `e`
  is: a method returning a helper's `*liberrors.Error` never returns a
  non-nil error holding a nil pointer.
- **`Convert[T](v) (T, error)`** is `v` as a `T` through JSON: a stored
  object (`rbac.Group`) as its contract's type (`api.Group`), or the other
  way. Both are written the same, field by field.
