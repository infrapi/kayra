---
title: identity
description: "Kayra's own identities - the reserved system: prefix, service account subjects and their groups, the kinds of caller."
weight: 75
---

# identity

```go
import "github.com/infrapi/kayra/internal/identity"
```

Names the identities Kayra issues itself, as opposed to the humans an
identity provider vouches for. Every subject under the reserved `system:`
prefix is one of Kayra's. [middleware](middleware.md#kayras-own-identities)
refuses a provider's user id under it, so no directory account can pose as
one.

```go
identity.ServiceAccount("core", "deployer")      // "system:serviceaccount:core:deployer"
ns, name, ok := identity.ParseServiceAccount(sub) // "core", "deployer", true
identity.ServiceAccountGroups("core")            // ["system:serviceaccounts", "system:serviceaccounts:core"]
identity.NamespaceServiceAccounts("core")        // "system:serviceaccounts:core"
identity.IsReserved("system:anything")           // true
identity.ValidName("deployer")                   // a DNS label
```

`KindUser` and `KindServiceAccount` are the values of
[`middleware.AuthContext.Kind`](middleware.md#authcontext), shown by
`/oauth2/userinfo` as `kind`. See
[Service accounts](../architecture/service-accounts.md).
