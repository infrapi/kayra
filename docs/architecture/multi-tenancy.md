---
title: Multi-tenancy
description: "How several teams or customers share one platform with Kayra: a tenant is not a namespace but owns some, what namespaces, RBAC and subscriptions isolate, what the APIs must isolate themselves, and when to run a Kayra per tenant."
weight: 15
---

# Multi-tenancy

Several teams, or several customers, can share one platform: one Kayra,
one gateway, the same APIs. This page says how, after Kubernetes'
[multi-tenancy](https://kubernetes.io/docs/concepts/security/multi-tenancy/)
guide, whose model Kayra follows.

## Terminology

- **A tenant** is who shares the platform. Kayra has no tenant object:
  - **multi-team:** a tenant is usually a team, whose people call the APIs
    themselves, with [`infrapi-cli`](https://infrapi.github.io/cli/getting-started/#1-install)
    or from their CI;
  - **multi-customer:** a tenant is a customer, whose users may never call
    Kayra themselves: a portal, or your own service, calls the APIs for
    them.
- **A namespace** is Kayra's unit of isolation: the names, the RBAC, the
  subscriptions to APIs and the events inside it are its own. A namespace is
  **not** a tenant: a tenant owns one or several namespaces (`acme-prod`,
  `acme-dev`, one per environment or per workload).
- **Isolation** applies to two planes:
  - the **control plane**, Kayra and the APIs' endpoints: who may call
    what, in which namespace;
  - the **data plane**, what the APIs provision (VMs, buckets, DNS
    zones): whether one tenant's resources can reach another's.
- **Soft or hard:** soft multi-tenancy trusts the tenants not to attack each
  other, a company's teams say. Hard multi-tenancy assumes they might, a
  vendor's customers say, and needs isolation in the data plane too. It is a
  spectrum, not a switch.

## What Kayra isolates (control plane)

| Mechanism | What it isolates |
|---|---|
| [Namespaces](namespaces.md) | Every API's resources are addressed in a namespace, `/apis/<group>/v1/namespaces/<ns>/...`, and decided by that namespace's RBAC. No API has cluster-scoped resources of its own. |
| [Namespace RBAC](auth/rbac-and-auth.md#the-rbac-model) | A namespace's groups, roles and bindings grant its members access, and nobody else's. A user not in any of its groups is refused, without learning what it is subscribed to. |
| [Cluster RBAC](auth/rbac-and-auth.md#who-can-manage-a-namespaces-rbac-objects) | A cluster group and binding scoped to a namespace make its admins, and only them, able to manage its RBAC. Global cluster roles belong to the platform's admins. |
| [Subscriptions](subscriptions.md) | A namespace uses an API only once subscribed. A registration's `allowed_namespaces` restricts who may subscribe. |
| [Service accounts](auth/service-accounts.md) | A namespace's machine identities act in that namespace only, never in another, even with a binding. |
| [API identity](auth/api-identity.md) | An API acts in a namespace with that namespace's grant, and [reports events](events.md) only in the namespaces subscribed to it. |
| [Personal access tokens](auth/tokens.md) | A token scoped to some APIs and verbs, whatever its user may do. |
| [Audit](audit.md) | Who asked for what, in which namespace, and whether it was allowed. |

Kayra has no quotas: how much a namespace may provision is each API's
business, as is everything in the data plane.

## What the APIs isolate (data plane)

Kayra decides who may call an API, not what the API's backend does. A
VM of `acme-prod` and a VM of `globex-prod` may run on the same hypervisor,
in the same cloud account, unless the API separates them:

- **Credentials per namespace:** [tofu-api](https://infrapi.github.io/tofu-api/)
  runs a provider per namespace with that namespace's credentials from
  Vault: a tenant reaches only what its own account allows.
- **Provisioning on subscription:** when a namespace subscribes, the
  reconciler calls the API ([Subscriptions](subscriptions.md)), which can
  create what the namespace needs of its own: an account, a VPC, a DNS
  zone.
- **The namespace from the URL, never from the body:** an API built on
  infrapi/lib reads the namespace a request acts in from its path, the one
  Kayra authorized.

For hard multi-tenancy, check each API's data plane: shared hosts, shared
networks and shared storage are the API's to separate.

## Tenancy models

### Namespaces per tenant, one Kayra

The default, and what this documentation describes. Each tenant gets its
namespaces; the platform's admins create them and hand each tenant's admins
their RBAC.

- **Cost:** a namespace is a few keys in etcd.
- **Sharing:** the APIs, the gateway and Kayra are shared; a group naming
  people of two tenants can grant both, when that is the intent.
- **Limits:** Kayra itself, its cluster RBAC and the API registrations are
  shared. A tenant cannot register an API of its own without the platform's
  admins.

### A Kayra per tenant

For hard multi-tenancy, or a tenant that must own its control plane: a
Kayra, its etcd (or its own `database.etcd.prefix`) and its gateway per
tenant, each a platform of its own (`app.platform`, `app.region`).

- **Isolation:** nothing is shared but what you choose to: the APIs'
  deployments may be shared, registered in each Kayra.
- **Cost:** as many Kayras to run, upgrade and audit; an API reconciled by
  each.

## Setting up a tenant

`acme`, a team with a production and a development namespace, its admins
in the directory group `sandbox-acme-admins`.

### 1. Create its namespaces

**infrapi-cli**

```bash
infrapi-cli create namespaces -d '{"name": "acme-prod"}'
infrapi-cli create namespaces -d '{"name": "acme-dev"}'
```

**curl**

```bash
for ns in acme-prod acme-dev; do
  curl -s -X POST https://kayra.example.com/apis/system.infrapi.io/v1/namespaces \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{\"name\": \"$ns\"}"
done
```

### 2. Make its admins the admins of each

A cluster group of the tenant's admins, a cluster role on the namespace's
RBAC objects, and a binding, each scoped to the namespace
(`metadata.namespace`). Repeat for `acme-dev`:

**infrapi-cli**

```bash
M='"metadata": {"namespace": "acme-prod", "region": "eu-west-1", "platform": "sandbox"}'
infrapi-cli create clustergroups -d "{\"name\": \"acme-prod-admins\", $M, \"groups\": [\"sandbox-acme-admins\"]}"
infrapi-cli create clusterroles -d "{\"name\": \"acme-prod-admin\", $M, \"rules\": [
  {\"apis\": [\"authorization.infrapi.io\"], \"resources\": [\"*\"], \"verbs\": [\"*\"]},
  {\"apis\": [\"catalog.infrapi.io\"], \"resources\": [\"subscriptions\"], \"verbs\": [\"*\"]}]}"
infrapi-cli create clusterrolebindings -d "{\"name\": \"acme-prod-admins\", $M, \"role\": \"acme-prod-admin\", \"groups\": [\"acme-prod-admins\"]}"
```

**curl**

```bash
A=https://kayra.example.com/apis/authorization.infrapi.io/v1
H=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")
M='"metadata": {"namespace": "acme-prod", "region": "eu-west-1", "platform": "sandbox"}'
curl -s -X POST $A/clustergroups "${H[@]}" -d "{\"name\": \"acme-prod-admins\", $M, \"groups\": [\"sandbox-acme-admins\"]}"
curl -s -X POST $A/clusterroles "${H[@]}" -d "{\"name\": \"acme-prod-admin\", $M, \"rules\": [
  {\"apis\": [\"authorization.infrapi.io\"], \"resources\": [\"*\"], \"verbs\": [\"*\"]},
  {\"apis\": [\"catalog.infrapi.io\"], \"resources\": [\"subscriptions\"], \"verbs\": [\"*\"]}]}"
curl -s -X POST $A/clusterrolebindings "${H[@]}" -d "{\"name\": \"acme-prod-admins\", $M, \"role\": \"acme-prod-admin\", \"groups\": [\"acme-prod-admins\"]}"
```

From then on, acme's admins subscribe their namespaces to the APIs and
grant their own people, in their namespaces only (see
[Subscriptions](subscriptions.md) and [RBAC & auth](auth/rbac-and-auth.md)).

### 3. Restrict an API to some tenants

An API only some tenants may use lists their namespaces in its
registration's `allowed_namespaces` (see
[API registrations](api-registrations.md#managing-one)).

## Naming

- **Prefix a namespace with its tenant:** `acme-prod`, not `prod`. A
  namespace's name is all a role, an audit record or an event says of whom it
  belongs to.
- **Keep names unique across your Kayras,** every platform and region: a
  tenant can then move between a shared Kayra and its own, and the audit of
  all of them reads the same.
