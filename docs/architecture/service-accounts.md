---
title: Service accounts
description: "A namespace's machine identities, system:serviceaccount:<namespace>:<name>, their rights in their own namespace only, and their short-lived tokens."
weight: 22
---

# Service accounts

A service account is a machine identity that belongs to one namespace: a CI
pipeline, a script, an operator. Its subject is
`system:serviceaccount:<namespace>:<name>`. It holds no secret: you ask Kayra
for a token when you need one, and the token lasts 24 hours at most. As in
Kubernetes, a service account can act **only in its own namespace**.

The examples use [`infrapi-cli`](https://infrapi.github.io/cli/getting-started/#1-install)
against a Kayra at `https://kayra.example.com`, with the `core` namespace. You
need the rights to manage that namespace's RBAC objects, which are described
in [Who can manage a namespace's RBAC objects](rbac-and-auth.md#who-can-manage-a-namespaces-rbac-objects).
Tokens are signed by the [authorization server](oauth2-server.md), so
`oauth2.enabled` must be set.

## 1. Create the service account

**infrapi-cli**

```bash
infrapi-cli create serviceaccounts -n core -d '{"name": "deployer", "description": "compute CI"}'
```

**curl**

```bash
curl -s -X POST https://kayra.example.com/apis/authorization.infrapi.io/v1/namespaces/core/serviceaccounts \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "deployer", "description": "compute CI"}'
```

- **Name:** a DNS label (lower case letters, digits and `-`).
- **`uid`:** Kayra sets it, and it never changes. Every token carries it.
  Once the service account is deleted, its tokens are refused, even after
  another one is created under the same name.
- **Other routes:**
  - `get serviceaccounts`, `get serviceaccounts deployer`;
  - `update` changes the description only;
  - `delete serviceaccounts deployer` ends every token it was issued.

## 2. Give it rights

A service account gets its rights through its namespace's RBAC, like anyone
else: a namespace **group** names it, and a **rolebinding** binds that group
to a role.

**infrapi-cli**

```bash
M='"metadata": {"namespace": "core", "region": "eu-west-1", "platform": "sandbox"}'
infrapi-cli create groups -n core -d "{\"name\": \"ci\", $M, \"serviceaccounts\": [\"deployer\"]}"
infrapi-cli create rolebindings -n core -d "{\"name\": \"ci-deploy\", $M, \"role\": \"deployer\", \"groups\": [\"ci\"]}"
```

**curl**

```bash
M='"metadata": {"namespace": "core", "region": "eu-west-1", "platform": "sandbox"}'
curl -s -X POST https://kayra.example.com/apis/authorization.infrapi.io/v1/namespaces/core/groups \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"name\": \"ci\", $M, \"serviceaccounts\": [\"deployer\"]}"
curl -s -X POST https://kayra.example.com/apis/authorization.infrapi.io/v1/namespaces/core/rolebindings \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"name\": \"ci-deploy\", $M, \"role\": \"deployer\", \"groups\": [\"ci\"]}"
```

To grant **every** service account of the namespace at once, name the group
`system:serviceaccounts:core` in the group's `groups`.

A service account **never** acts outside its namespace:

- **Only its namespace's groups count it.** A group of another namespace never
  matches it, even one naming it. A wildcard (`users: ["*"]`, `groups: ["*"]`)
  never matches a service account.
- **A cluster group cannot name a service account.** It is refused with a 400.
  A service account therefore holds nothing cluster-scoped, and never manages
  RBAC objects, not even its own namespace's.
- **The `system:` prefix is reserved.** A user id an identity provider
  resolves under it is refused. A `system:` entry in a group's `users` is
  refused too, and the reserved groups are dropped from a human's groups. No
  directory account can pose as a service account.

## 3. Get a token

The token action is a permission of its own,
`authorization.infrapi.io` / `serviceaccounts/token` / `create`. You can let a
pipeline's admins create tokens without letting them manage the service
accounts.

> [!WARNING]
> Whoever can create a service account's tokens can act with its rights.
> Grant `serviceaccounts/token` as you would grant the service account's
> roles.

**infrapi-cli**

```bash
infrapi-cli create serviceaccounts/token deployer -n core -d '{"expires_in": "1h", "audience": ["https://compute.example.com"]}'
```

**curl**

```bash
curl -s -X POST https://kayra.example.com/apis/authorization.infrapi.io/v1/namespaces/core/serviceaccounts/deployer/token \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"expires_in": "1h", "audience": ["https://compute.example.com"]}'
# {"token":"eyJ…","expires_at":"2026-11-23T18:17:51Z"}
```

- **`expires_in`:** the token's lifetime. When empty it is
  `serviceaccounts.token_ttl` (1h), and it is capped by
  `serviceaccounts.max_token_ttl` (24h at most):
  ```yaml
  serviceaccounts:
    token_ttl: 1h
    max_token_ttl: 24h
  ```
  A CI that needs a token for longer asks for a new one.
- **`audience`:** the resources the token is for, among `oauth2.resources`.
  It defaults to Kayra's own. An app built on infrapi/lib refuses a token
  whose `aud` is not its own.
- **Revoking one token:** `POST /oauth2/revoke` with `token` and
  `client_id=system:serviceaccount:core:deployer`. To revoke all of them,
  delete the service account.

In a CI, or anywhere the platform issues an identity of its own (GitLab CI,
GitHub Actions, Kubernetes), **don't keep a token at all**: log in with the
platform's identity token instead. See [Federation](federation.md).

## 4. Use it

The token is a bearer token like any other. Save it in a context of
`infrapi-cli`:

**infrapi-cli**

```bash
infrapi-cli auth context set ci --server https://kayra.example.com --token "$SA_TOKEN"
infrapi-cli auth whoami
# kind:    serviceaccount
# sub:     system:serviceaccount:core:deployer
# groups:  system:serviceaccounts, system:serviceaccounts:core
```

**curl**

```bash
curl -s https://kayra.example.com/oauth2/userinfo -H "Authorization: Bearer $SA_TOKEN"
# {"sub":"system:serviceaccount:core:deployer","kind":"serviceaccount","groups":["system:serviceaccounts","system:serviceaccounts:core"],…}
```

Kayra resolves it from its own store, not through an authorization backend.
The service account must still exist with the token's `uid`, and its
namespace must still exist.
