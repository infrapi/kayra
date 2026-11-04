# Getting started

A full walkthrough: build, run, bootstrap a token, and create a tenant
all the way through to a running subscription — every command below is
copy-pasteable `curl`.

## 1. Build

```bash
go build -o kayra ./cmd/kayra
go build -o kayra-cli ./cmd/cli
```

`kayra` runs the server and its background jobs. `kayra-cli` is the
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
./kayra --config kayra.yaml serve &
./kayra --config kayra.yaml reconciler &
```

## 4. Mint a bootstrap token

A brand new deployment has no user, group or RBAC object yet, so
there's nothing to log in *against*. `token mint` signs a JWT directly
from the config's own local key — the one way in before any of that
exists:

```bash
TOKEN=$(./kayra --config kayra.yaml token mint \
  --provider self --group sandbox-core-sysadmin --ttl 1h)
```

That token satisfies `sysadmin.groups` above, so it can call every
cluster-bootstrap endpoint below. Past this point, a real deployment
switches to real logins (`kayra-cli login`, see [CLI](cli.md)) and
mints this bootstrap token only when actually needed again.

## 5. Create a tenant

A namespace *is* a tenant — one call creates both:

```bash
curl -s -X POST http://localhost:8080/apis/apps.example.com/v1/namespaces \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "thetenant"}'
# {"active":false,"name":"thetenant"}
```

It comes back `active: false` — only `kayra reconciler` ever flips
that (see [Namespaces](architecture/namespaces.md)).

## 6. Grant a group access to it

Group → role → rolebinding, cluster-scoped, so this tenant's own
admins can later manage its day-to-day RBAC themselves:

```bash
curl -s -X POST http://localhost:8080/apis/authorization.example.com/v1/clustergroups \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "thetenant-admins",
       "metadata": {"namespace": "thetenant", "region": "eu-west-1", "platform": "sandbox"},
       "groups": ["sandbox-thetenant-admins"]}'

curl -s -X POST http://localhost:8080/apis/authorization.example.com/v1/clusterroles \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "thetenant-admin-role",
       "metadata": {"namespace": "thetenant", "region": "eu-west-1", "platform": "sandbox"},
       "rules": [{"apis": ["subscription.example.com"], "resources": ["*"], "verbs": ["*"]}]}'

curl -s -X POST http://localhost:8080/apis/authorization.example.com/v1/clusterrolebindings \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "thetenant-admin-binding",
       "metadata": {"namespace": "thetenant", "region": "eu-west-1", "platform": "sandbox"},
       "role": "thetenant-admin-role", "groups": ["thetenant-admins"]}'
```

See [who can manage a namespace's RBAC](architecture/rbac-and-auth.md)
for how this check is actually evaluated.

## 7. Create a stack and subscribe the tenant to it

`Stack` is cluster-wide infrastructure (e.g. "vault"); a `Subscription`
links one namespace to one stack by name:

```bash
curl -s -X POST http://localhost:8080/apis/catalog.example.com/v1/stacks \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "vault", "owner": "sre"}'
# sync_id is minted automatically — note it down, or just GET it back below

curl -s -X POST http://localhost:8080/apis/subscription.example.com/v1/namespaces/thetenant/subscriptions \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"stack_name": "vault"}'
# {"stack_name":"vault","active":false,"state":"init", ...}
```

Any caller whose groups are bound to the `subscription.example.com` API
(step 6's rolebinding covers this) can do the subscribe step — it
doesn't have to be the bootstrap token.

## 8. Trigger a sync and check status

```bash
curl -s -X PUT http://localhost:8080/apis/catalog.example.com/v1/stacks/vault/sync \
  -H "Authorization: Bearer $TOKEN"

curl -s http://localhost:8080/apis/catalog.example.com/v1/stacks/vault/status \
  -H "Authorization: Bearer $TOKEN"
```

`kayra reconciler` picks up the new `sync_id` and runs whichever HTTP
step pipeline `reconciler.mode` configures (none here, so it just logs
and activates directly) — see
[Subscriptions & reconciliation](architecture/subscriptions.md) for the
full reconcile model.

## What's next

- [CLI reference](cli.md) — `kayra-cli login`, contexts, personal
  access tokens.
- [Architecture](architecture/overview.md) — how every package fits
  together.
- [Config reference](packages/config.md) — every YAML key.
