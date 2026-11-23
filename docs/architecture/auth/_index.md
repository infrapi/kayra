---
title: Authentication and authorization
description: "Who is calling, how it proves it, and what it may do: the identities Kayra knows, every way to authenticate and when to use each, a provider's token versus federation, a service account versus the ways it logs in, and how access is decided."
weight: 11
---

# Authentication and authorization

Every request to Kayra, or to an API behind it, answers three questions:

1. **Who is calling?** An **identity**: a person, a service account, an API.
2. **How does it prove it?** **Authentication**: a token Kayra verifies.
3. **What may it do?** **Authorization**: the RBAC, decided by Kayra on every
   request (`/check`).

The three are separate: a person may authenticate in several ways and keep
the same rights; a service account is one identity whichever way it logs
in. This page says which identity and which way fit which use, then points to
the page of each. The pages of this section:

- [RBAC & auth](rbac-and-auth.md): how a token is verified, and how the RBAC
  decides.
- [Authorization server](oauth2-server.md): Kayra's own tokens, for
  `infrapi-cli auth login` and MCP clients, renewed and revoked.
- [Personal access tokens](tokens.md): a user's long-lived tokens for
  scripts and tools, expiring, scoped, revocable.
- [Service accounts](service-accounts.md): a namespace's machine identities
  and their short-lived tokens.
- [Federation](federation.md): a CI job or a workload logs in as a service
  account with its platform's token, no secret stored.
- [API identity](api-identity.md): the app behind a registered API acts as
  the API, with its own key.

## Identities

| Identity | Subject | Defined by | Its rights |
|---|---|---|---|
| **A user**, a person | their id at your identity provider: `jdoe` | your identity provider (Okta, GitLab, LDAP...), never Kayra | the groups your directory says they are in, bound to roles (`authorizations:` resolves them) |
| **A [service account](service-accounts.md)**, a machine of a namespace | `system:serviceaccount:<namespace>:<name>` | a namespace's admins, in Kayra | the roles of its namespace's groups that name it; in that namespace only |
| **An [API](api-identity.md)**, the app behind a registered API | `system:api:<group>` | the API's registration, in Kayra | reading its own registration; anything else, the groups that name it in `apis` |

A user's identity lives outside Kayra: Kayra only checks that a provider
vouches for it. A service account's and an API's live in Kayra: `system:` is
reserved for them, and no provider's user can take that prefix.

## Authentication: pick by use

| You are... | and want to... | Use | You get |
|---|---|---|---|
| a person at a terminal | call the APIs | [`infrapi-cli auth login`](oauth2-server.md) | a Kayra token for you, renewed |
| a person's script, a tool | call as you, without a browser | a [personal access token](tokens.md) | `pat_…`, as you, scoped, expiring |
| an AI agent (an MCP client) | call tools as its user | the [authorization server](oauth2-server.md)'s OAuth login, or [ulgen](https://infrapi.github.io/ulgen/) | a Kayra token for its user |
| a CI job | act **as the person who ran it** | the provider's token, accepted as is ([below](#a-providers-token-or-federation)) | no exchange: the job's token is the bearer |
| a CI job, a pod | act **as a machine of a namespace**, no secret stored | [federation](federation.md) | a 15-minute token of a service account |
| a workload with no platform identity | act as a machine of a namespace | a [service account](service-accounts.md)'s own key, or its token action | a token of the service account |
| an API's app | call Kayra or another API **as the API** | its [API identity](api-identity.md): its own key, or federation | a 15-minute token of `system:api:<group>` |

Whichever way, a request carries one bearer token, and Kayra resolves it to
the same thing: a subject, its groups, its kind (`user`, `serviceaccount`,
`api`). `infrapi-cli auth whoami` shows it.

### The ways, defined

- **A provider's token.** A token another provider issued (Okta, Dex, a
  GitLab CI job's `id_token`), checked by Kayra on every request against that
  provider's keys and the claims `authentifications.<name>` requires. The
  caller is the user the token names.
- **A login at Kayra.** `infrapi-cli auth login`, an MCP client: Kayra sends
  the person to their provider, checks the provider's answer, then issues a
  token of its own (its **authorization server**, the OAuth term for what
  issues tokens). The caller is still that user.
- **A personal access token.** A user's own long-lived secret, `pat_…`,
  that expires and can be scoped and revoked.
- **A service account's token action.** A token Kayra signs on request for
  a service account, at most 24 hours, kept wherever it is used.
- **Federation.** A platform vouches for a workload (GitLab CI, GitHub
  Actions, Kubernetes), and Kayra trusts that platform's token as one of its
  own identities, a service account or an API, when it matches one of the
  identity's **federated credentials**. Kayra then issues that identity's
  token (OAuth `client_credentials`).
- **An identity's own key.** A service account or an API signs an
  assertion with its private key; Kayra holds the public half
  (`private_key_jwt`). Same exchange as federation, a key instead of a
  platform's token.

## A provider's token, or federation

Both let a CI job call InfraPI with the token its platform gives it, with no
secret stored. They answer a different question: **who does the audit say
acted?**

### A provider's token: the job acts as its user

```yaml
authentifications:
  gitlab:
    authorization: idm                 # the directory that resolves the user's groups
    remote:
      enabled: true
      url: https://gitlab.example.com/.well-known/openid-configuration
      # a CI job's token asks for it: id_tokens: {INFRAPI_TOKEN: {aud: ...}}
      claims:
        aud: "api://infrapi-$region-$platform"
      user_id:
        from: token
        field: user_login               # the GitLab user who ran the pipeline
```

The job sends its `id_token` as its bearer token, to Kayra and to every API:

- **Who acts:** the user who ran the pipeline (`user_login`), `jdoe`.
- **With which rights:** all of `jdoe`'s, in every namespace, from `jdoe`'s
  groups.
- **Which jobs get in:** any job of any project on that GitLab whose token
  asks for that `aud`: a merge request's pipeline, a developer's branch, a
  schedule (run as its owner). The `claims` can require more of every token,
  but they apply to all of them alike.
- **Who decides:** Kayra's admin, in `kayra.yaml`.
- **Lifetime:** the job token's own; Kayra issues nothing.

### Federation: the job acts as a service account

```yaml
federation:
  issuers:
    - issuer: https://gitlab.example.com
```

```json
{"name": "deployer", "federated_credentials": [
  {"name": "gitlab-main", "issuer": "https://gitlab.example.com",
   "subject": "project_path:infra/compute:ref_type:branch:ref:main"}]}
```

The job exchanges its `id_token` for the service account's token
(`infrapi-cli auth login --service-account core/deployer --id-token
env:KAYRA_ID_TOKEN`):

- **Who acts:** `system:serviceaccount:core:deployer`, whoever ran the
  pipeline.
- **With which rights:** the service account's, in `core` only.
- **Which jobs get in:** those whose token matches a credential exactly: this
  project, this branch (or environment, or protected ref). Another branch, a
  fork, a merge request: refused.
- **Who decides:** Kayra's admin lists the trusted issuers; the namespace's
  admins say which jobs are their service account.
- **Lifetime:** Kayra's token, 15 minutes, asked again with the job's token.

### Side by side

| | A provider's token | Federation |
|---|---|---|
| The caller | the user who ran the job | a service account of a namespace |
| Its rights | the user's, everywhere | the service account's, in its namespace |
| Trusted jobs | every job of the provider asking for the `aud` | the jobs a federated credential matches: project, branch, environment |
| Configured by | Kayra's admin, `authentifications:` | Kayra's admin (`federation.issuers`) and the namespace's admins (`federated_credentials`) |
| The token APIs see | the provider's | Kayra's, its `aud` the resource asked for |
| Survives | the user leaving: no, their groups go | the person leaving: yes, the pipeline keeps working |
| Fits | a person's own pipeline, acting as them on purpose | a deployment pipeline, a release, a scheduled job |

Use the provider's token when the job must act as its person, with their
rights and their name in the audit. Use federation for everything a pipeline
does as the project: its rights are the namespace's to grant, limited to
what it deploys, and they do not follow whoever pushed.

## A service account, and how it logs in

A service account is an **identity**: a subject, the groups that name it, its
rights in its namespace. Federation, its own key and its token action are
**ways to prove** you are it, interchangeable:

| To get a service account's token | Holds a secret? | Lifetime | Fits |
|---|---|---|---|
| [Federation](federation.md): a platform's token (GitLab CI, GitHub Actions, Kubernetes) | no | 15 minutes, asked again | a CI job, a pod |
| [Its own key](federation.md#a-key-of-its-own-instead-private_key_jwt): an assertion signed by it | the private key, never sent | 15 minutes, asked again | a workload with no platform identity |
| [Its token action](service-accounts.md#3-get-a-token): asked by someone allowed `serviceaccounts/token` | the token itself | up to 24 hours | a one-off, a test, a system that only takes a static token |

Its rights do not depend on the way. Removing a way (a federated credential,
a key) removes nobody's rights; deleting the service account ends every
token, whichever way it came.

An [API identity](api-identity.md) is the same for an API's app: one
identity, `system:api:<group>`, and its own key or federation to prove it.

## Authorization: what decides

Once authenticated, every request is decided by Kayra, whatever the API:

| Request | Decided by |
|---|---|
| an API's resources in a namespace | the namespace's own [groups, roles and bindings](rbac-and-auth.md#the-rbac-model), once the namespace is [subscribed](../subscriptions.md) to the API |
| managing a namespace (its RBAC, its subscriptions) | the [cluster bindings scoped to it](rbac-and-auth.md#who-can-manage-a-namespaces-rbac-objects) |
| cluster-scoped resources (namespaces, API registrations, the cluster RBAC) | the [cluster RBAC](rbac-and-auth.md#who-decides), the sysadmin binding first |

On top of the roles:

- **A PAT's scope** narrows what its user may do.
- **A service account** is matched only by groups of its own namespace.
- **An API** may always read its own registration, and
  [report events](../events.md) about its own objects.
- **A registration's `allowed_namespaces`** keeps other namespaces out.

An app built on infrapi/lib asks Kayra's `/check` for each request; `infrapi-cli
auth can-i` asks the same question. Every decision is in the
[audit](../audit.md). See [RBAC & auth](rbac-and-auth.md) for the model, and
[Multi-tenancy](../multi-tenancy.md) for sharing the platform between teams.

## Terms

| Term | In Kayra |
|---|---|
| identity provider | your Okta, GitLab, Dex, LDAP: where people are defined |
| `authentifications:` | the providers whose tokens Kayra accepts, and how to read the user from a token |
| `authorizations:` | where a user's **groups** are resolved (LDAP, a file, the token's own claims). Not the RBAC, despite its name |
| authorization server | Kayra's OAuth server: what **issues** Kayra's tokens (logins, `client_credentials`). Not what decides access |
| access token | the bearer token of a request: a provider's, Kayra's, or a PAT |
| identity token | a platform's token naming a workload (a GitLab CI job's `id_token`): presented to Kayra, never to an API, under federation |
| audience (`aud`) | whom a token is for: Kayra's or an API's URL |
| federated credential | on a service account or an API: which platform tokens are it (issuer, subject, claims) |
| `client_credentials` | the OAuth grant a service account or an API gets its token with |
| RBAC | groups, roles and bindings: who may do what, where |
