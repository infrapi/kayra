---
title: Getting started
description: Install Kayra, run it, bootstrap a token and create a tenant through to a running subscription.
weight: 20
---

# Getting started

A full walkthrough: install, run, bootstrap a token, and create a tenant
all the way through to a running subscription — every command below is
copy-pasteable `infrapi-cli`, with its raw `curl` equivalent in the
block that follows it.

## 1. Install

Two binaries: `kayra`, the server, published on every
[Kayra release](https://github.com/infrapi/kayra/releases)
(`kayra_<version>_<os>_<arch>`), and `infrapi-cli`, the client, on every
[CLI release](https://github.com/infrapi/cli/releases). Install them with
[bin](https://github.com/marcosnils/bin/), which picks the archive
matching your OS/arch, extracts the binary onto your `PATH` and tracks
it for later `bin update`:

```bash
bin install github.com/infrapi/kayra ~/.local/bin/kayra
bin install github.com/infrapi/cli ~/.local/bin/infrapi-cli

bin list    # both tracked, so `bin update` upgrades them together
```

See [infrapi-cli's docs](https://infrapi.github.io/cli/) for the client.

### Or the container image

Every release also publishes an image, `ghcr.io/infrapi/kayra`, for
`linux/amd64` and `linux/arm64`. It is tagged with the release's version
(`<major>.<minor>.<patch>`), its minor (`<major>.<minor>`) and `latest`. Pin
one of the first two in a deployment. It holds `kayra` and no
configuration: mount yours at `/etc/kayra/kayra.yaml` (`KAYRA_CONFIG_FILE`).
The entrypoint is `kayra`, and the default command `serve`:

```bash
podman run --rm -v ./kayra.yaml:/etc/kayra/kayra.yaml:ro,z -p 8080:8080 ghcr.io/infrapi/kayra:latest
podman run --rm -v ./kayra.yaml:/etc/kayra/kayra.yaml:ro,z ghcr.io/infrapi/kayra:latest reconciler
```

It runs as an unprivileged user (uid 10001) and carries `curl` for a
healthcheck on `/apis/system.<domain>/v1/-/healthz`.

<details>
<summary>Building from source instead</summary>

```bash
go build -o kayra ./cmd/kayra
go install github.com/infrapi/cli/cmd/infrapi-cli@latest
```

</details>

`kayra` runs the server and its background jobs. `infrapi-cli` is the
separate, portable client an end user logs in with — it never reads
`kayra.yaml` or touches local config at all (see [CLI](cli.md)).

## 2. Write a config

One YAML file covers everything. This one uses a local on-disk store
instead of etcd and a local fixture instead of real LDAP — good enough
to try things out, see [config](packages/config.md) for every option.

```yaml title="kayra.yaml"
app:
  name: "kayra"
  url: "http://localhost:8080"
  platform: "sandbox"
  region: "eu-west-1"
  location: "dc1"
  listen_type: "tcp"
  listen_address: "127.0.0.1:8080"

database:
  main:
    local:
      path: /tmp/kayra-db

authorizations:
  # A self-signed token's own groups claim is trusted directly — no
  # directory round trip needed. This is what makes `token mint`
  # below work on a deployment with nothing else configured yet.
  self-claims:
    claims:
      from: token
      groups_field: groups

authentifications:
  self:
    authorization: self-claims
    local:
      - enabled: true
        algorithm: RS512
        issuer: true
        kid: dev-key
        # generate your own: openssl genrsa 2048
        secret: |
          -----BEGIN PRIVATE KEY-----
          ...
          -----END PRIVATE KEY-----

sysadmin:
  groups: ["sandbox-core-sysadmin"]
```

## 3. Start the server and the reconciler

Two separate processes, each with its own lifecycle:

```bash
kayra --config kayra.yaml serve &
kayra --config kayra.yaml reconciler &
```

## 4. Mint a bootstrap token

A brand new deployment has no user, group or RBAC object yet, so
there's nothing to log in *against*. `token mint` signs a JWT directly
from the config's own local key — the one way in before any of that
exists:

```bash
TOKEN=$(kayra --config kayra.yaml token mint \
  --provider self --group sandbox-core-sysadmin --ttl 1h)

# save it as a infrapi-cli context — every command below uses it
infrapi-cli auth context set bootstrap --server http://localhost:8080 --token "$TOKEN"
```

That token satisfies `sysadmin.groups` above, so it can call every
cluster-bootstrap endpoint below. Past this point, a real deployment
switches to real logins (`infrapi-cli login`, see [CLI](cli.md)) and
mints this bootstrap token only when actually needed again.

## 5. Create a tenant

A namespace *is* a tenant — one call creates both:

**infrapi-cli**

```bash
infrapi-cli create system namespaces -d '{"name": "thetenant"}'
# {"active": false, "name": "thetenant"}
```

**curl**

```bash
curl -s -X POST http://localhost:8080/apis/system.infrapi.io/v1/namespaces \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "thetenant"}'
# {"active": false, "name": "thetenant"}
```

It comes back `active: false` — only `kayra reconciler` ever flips
that (see [Namespaces](architecture/namespaces.md)).

## 6. Grant a group access to it

Group → role → rolebinding, cluster-scoped, so this tenant's own
admins can later manage its day-to-day RBAC themselves:

**infrapi-cli**

```bash
infrapi-cli create authorization clustergroups -d '{"name": "thetenant-admins",
       "metadata": {"namespace": "thetenant", "region": "eu-west-1", "platform": "sandbox"},
       "groups": ["sandbox-core-sysadmin"]}'

infrapi-cli create authorization clusterroles -d '{"name": "thetenant-admin-role",
       "metadata": {"namespace": "thetenant", "region": "eu-west-1", "platform": "sandbox"},
       "rules": [{"apis": ["catalog.infrapi.io"], "resources": ["*"], "verbs": ["*"]}]}'

infrapi-cli create authorization clusterrolebindings -d '{"name": "thetenant-admin-binding",
       "metadata": {"namespace": "thetenant", "region": "eu-west-1", "platform": "sandbox"},
       "role": "thetenant-admin-role", "groups": ["thetenant-admins"]}'
```

**curl**

```bash
curl -s -X POST http://localhost:8080/apis/authorization.infrapi.io/v1/clustergroups \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "thetenant-admins",
       "metadata": {"namespace": "thetenant", "region": "eu-west-1", "platform": "sandbox"},
       "groups": ["sandbox-core-sysadmin"]}'

curl -s -X POST http://localhost:8080/apis/authorization.infrapi.io/v1/clusterroles \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "thetenant-admin-role",
       "metadata": {"namespace": "thetenant", "region": "eu-west-1", "platform": "sandbox"},
       "rules": [{"apis": ["catalog.infrapi.io"], "resources": ["*"], "verbs": ["*"]}]}'

curl -s -X POST http://localhost:8080/apis/authorization.infrapi.io/v1/clusterrolebindings \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "thetenant-admin-binding",
       "metadata": {"namespace": "thetenant", "region": "eu-west-1", "platform": "sandbox"},
       "role": "thetenant-admin-role", "groups": ["thetenant-admins"]}'
```

See [who can manage a namespace's RBAC](architecture/rbac-and-auth.md)
for how this check is actually evaluated.

## 7. Register an API and subscribe the tenant to it

An `ApiRegistration` declares that an API group exists (e.g. "vault.infrapi.io", its long name — its id)
and who owns it — Kayra never implements the API itself, only tracks
it and notifies on changes. A `Subscription` links one namespace to
one registration by name:

**infrapi-cli**

```bash
infrapi-cli create catalog apiregistrations \
  -d '{"name": "vault.infrapi.io", "short_name": "vault", "owner": "sre"}'
# sync_id is minted automatically — note it down, or just GET it back below

infrapi-cli create catalog -n thetenant subscriptions -d '{"api": "vault.infrapi.io"}'
# {"api": "vault.infrapi.io", "active": false, "state": "init", ...}
```

**curl**

```bash
curl -s -X POST http://localhost:8080/apis/catalog.infrapi.io/v1/apiregistrations \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "vault.infrapi.io", "short_name": "vault", "owner": "sre"}'
# sync_id is minted automatically — note it down, or just GET it back below

curl -s -X POST http://localhost:8080/apis/catalog.infrapi.io/v1/namespaces/thetenant/subscriptions \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"api": "vault.infrapi.io"}'
# {"api": "vault.infrapi.io", "active": false, "state": "init", ...}
```

Any caller whose groups are bound to the `catalog.infrapi.io` API
can do the subscribe step — it doesn't have to be the bootstrap token;
`$TOKEN` works here only because step 6's rolebinding happens to grant
`sandbox-core-sysadmin` (the bootstrap token's own group) that right
too. A real deployment would bind a tenant's actual admin group there
instead.

## 8. Trigger a sync and check status

**infrapi-cli**

```bash
infrapi-cli update catalog apiregistrations vault.infrapi.io/sync -d '{}'

infrapi-cli get catalog apiregistrations vault.infrapi.io/status
```

**curl**

```bash
curl -s -X PUT http://localhost:8080/apis/catalog.infrapi.io/v1/apiregistrations/vault.infrapi.io/sync \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{}'

curl -s http://localhost:8080/apis/catalog.infrapi.io/v1/apiregistrations/vault.infrapi.io/status \
  -H "Authorization: Bearer $TOKEN"
```

`kayra reconciler` picks up the new `sync_id` and runs whichever HTTP
step pipeline `reconciler.mode` configures (none here, so it just logs
and activates directly) — see
[Subscriptions & reconciliation](architecture/subscriptions.md) for the
full reconcile model.

## What's next

- [CLI reference](cli.md) — `infrapi-cli login`, contexts, personal
  access tokens.
- [Architecture](architecture/overview.md) — how every package fits
  together.
- [Config reference](packages/config.md) — every YAML key.
