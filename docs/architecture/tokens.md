---
title: Personal access tokens
description: "A user's long-lived tokens, for scripts and tools - every one expires, may be scoped to some APIs and verbs, is listed and revoked by its id."
weight: 23
---

# Personal access tokens

A personal access token (PAT) lets a script or a tool act as you without a
browser login. It is opaque (`pat_…`, not a JWT), and its record is encrypted
at rest. It follows these rules:

- **Every token expires.** The default is 30 days (`tokens.pat.ttl`), with
  90 days at most (`tokens.pat.max_ttl`).
- **A token may be scoped:** it then allows what both your rights and its
  scope allow.
- **A token is listed and revoked by its public id,** never by its secret.
- **Only a logged-in user creates one.** A PAT cannot create another, and a
  [service account](service-accounts.md) gets none: it logs in its own ways
  (see [Authentication and authorization](auth.md#a-service-account-and-how-it-logs-in)).

The examples use [`infrapi-cli`](https://infrapi.github.io/cli/getting-started/#1-install),
logged in to `https://kayra.example.com`.

## 1. Create one

**infrapi-cli**

```bash
infrapi-cli create tokens -d '{"name": "laptop", "expires_in": "720h", "scope": {"apis": ["compute.infrapi.io"], "verbs": ["get", "list"]}}' -o yaml
```

**curl**

```bash
curl -s -X POST https://kayra.example.com/apis/authorization.infrapi.io/v1/tokens \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "laptop", "expires_in": "720h", "scope": {"apis": ["compute.infrapi.io"], "verbs": ["get", "list"]}}'
# {"id":"qpmtejrtcysnbiilcuh7gch36f","name":"laptop","user":"jdoe","created_at":"…","expires_at":"…",
#  "scope":{"apis":["compute.infrapi.io"],"verbs":["get","list"]},"token":"pat_…"}
```

The `token` is shown **once**: keep it.

| Field | |
|---|---|
| `name` | What it is for. Required, 64 characters at most. |
| `expires_in` | Its lifetime, a duration: `tokens.pat.ttl` when empty, at most `tokens.pat.max_ttl`. |
| `scope` | `apis` (full API group names) and `verbs`, each wildcardable with `"*"`. Without a scope, the token allows everything you may do. |

```yaml
tokens:
  pat:
    ttl: 720h
    max_ttl: 2160h
```

## 2. What a scope allows

A scoped token sends only requests whose API and verb its scope grants. They
are read from the path as [`/check`](rbac-and-auth.md#authorizing-other-apps-requests)
reads them. A GET on a collection is `list`, a GET on a name is `get`, and so
on.

- **On Kayra's own routes:** a request outside the scope gets a 403.
- **In `/check`:** the scope is applied to the request being checked. An app
  built on infrapi/lib therefore refuses, with
  `your token's scope does not grant …`, a request your roles would allow.
- **Always allowed:** `/oauth2/userinfo` and the discovery, `GET /apis`.
  Anything else outside `/apis` is refused, sessions included.

## 3. List and revoke

**infrapi-cli**

```bash
infrapi-cli get tokens -o yaml
infrapi-cli delete tokens qpmtejrtcysnbiilcuh7gch36f
```

**curl**

```bash
curl -s https://kayra.example.com/apis/authorization.infrapi.io/v1/tokens -H "Authorization: Bearer $TOKEN"
curl -s -X DELETE https://kayra.example.com/apis/authorization.infrapi.io/v1/tokens/qpmtejrtcysnbiilcuh7gch36f -H "Authorization: Bearer $TOKEN"
```

- **What a list shows:** each token's id, name, dates, scope and
  `last_used_at` (updated at most once an hour), never its secret.
- **Revoking:** a revoked token gets a 401 at once. An expired one disappears
  by itself.
- **Another user's tokens:** add `?user=<id>` to the list or the delete. It
  needs `authorization.infrapi.io` / `tokens` / `list` or `delete` in a global
  cluster role; the [sysadmin](rbac-and-auth.md#the-sysadmin-binding) has
  them.

## Where the roles come from

A token has no roles of its own. When it is used, its user's groups are
resolved as for a login, live from the directory. The one exception is a
`claims` authorization backend, which has no directory to query again: there
the groups are those of the login that created the token (see
[crypto](../packages/crypto.md#pat-records)).
