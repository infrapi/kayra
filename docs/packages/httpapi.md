# httpapi

```go
import "github.com/infrapi/kayra/internal/httpapi"
```

Centralises how every Kayra handler turns an error into an HTTP response,
using [infrapi/lib's `pkg/errors`](https://infrapi.github.io/lib/packages/errors/)
RFC 9457 problem-detail payload.

```go
httpapi.Fail(c, liberrors.New(http.StatusNotFound, "catalog.GetStack", "stack %q not found", name))
```

Writes `err` as the response body (`liberrors.MediaType` content type) and
aborts the gin context, so no further handler in the chain runs — a
middleware refusing a request included. This is the one function every
route handler across [rbac](rbac.md), the
[catalog](../architecture/overview.md#catalog), [tokenapi](tokenapi.md) and
[middleware](middleware.md) calls on failure,
so every error response across the whole API has the identical shape.
