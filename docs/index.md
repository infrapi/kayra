---
title: Kayra
description: Kayra is the InfraPI authentication, namespace creation and IAM policy service.
weight: 10
---

# Kayra

Kayra is the authentication, namespace creation and IAM policy service,
built on [`infrapi/lib`](https://infrapi.github.io/lib/). Cluster-wide
**API registrations**, per-tenant **namespaces** and the
**subscriptions** linking them sit behind one bearer-auth and
cluster-RBAC model, with a separate `kayra reconciler` process turning
disabled records active.

## Where to start

| I want to... | Go to |
|---|---|
| Run Kayra for the first time | [Getting started](getting-started.md) |
| Understand how the pieces fit together | [Architecture overview](architecture/overview.md) |
| See who can authenticate and who can manage what | [RBAC & auth](architecture/rbac-and-auth.md) |
| Create or update an API registration | [API registrations](architecture/api-registrations.md) |
| Create or update a tenant | [Namespaces](architecture/namespaces.md) |
| Subscribe a tenant to an API registration, or trigger reconcile | [Subscriptions & reconciliation](architecture/subscriptions.md) |
| Run a command (`serve`, `reconciler`, `cache clean`, `token mint`) or use `infrapi-cli` | [CLI](cli.md) |
| Look up one `internal/*` package's API | [Packages](#packages) |
| Build, test, or work on the docs themselves | [Development](development.md) |

## Packages

Package-by-domain, not package-by-layer: each package below owns its
own types, storage and HTTP handlers together.

| Package | Owns |
|---|---|
| [`internal/config`](packages/config.md) | Loading and validating `kayra.yaml` |
| [`internal/store`](packages/store.md) | etcd / local storage backend |
| [`internal/crypto`](packages/crypto.md) | PAT encryption, self-signed JWT signing |
| [`internal/oidc`](packages/oidc.md) | Discovery/JWKS fetch, caching, own endpoints |
| [`internal/discovery`](packages/discovery.md) | `/.well-known/kayra.json`: the API domain, built-in groups and endpoints clients discover |
| [`internal/authn`](packages/authn.md) | Verifying a bearer token, resolving its user id |
| [`internal/authz`](packages/authz.md) | Resolving a user id to groups/attributes (LDAP or fixture) |
| [`internal/middleware`](packages/middleware.md) | The gin auth middleware |
| [`internal/rbac`](packages/rbac.md) | `Group`/`Role`/`RoleBinding`, cluster + namespace scoped |
| `internal/catalog` | `ApiRegistration`/`Namespace`/`Subscription` + the reconciler (see [API registrations](architecture/api-registrations.md), [Namespaces](architecture/namespaces.md), [Subscriptions & reconciliation](architecture/subscriptions.md)) |
| [`internal/tokenapi`](packages/tokenapi.md) | Personal access token issuance |
| `internal/oauth2server` | The [authorization server](architecture/oauth2-server.md): tokens of Kayra's own, renewed and revoked |
| [`internal/httpapi`](packages/httpapi.md) | RFC 9457 error response helper |
| [`internal/apiserver`](packages/apiserver.md) | Wires every package above onto one gin engine |

`cmd/kayra` wires all of it together. The end user's client,
[`infrapi-cli`](https://github.com/infrapi/cli), lives in its own
repository and only ever talks to Kayra's API.
