---
title: API identity
description: "A registered API's own identity, system:api:<group>: the app behind it gets its own tokens, with its key or its platform's token, and acts as the API."
weight: 60
---

# API identity

An API registered in Kayra can have an identity of its own:
`system:api:<group>`, `system:api:compute.infrapi.io` say. The app behind
it gets tokens as that identity, from Kayra's
[authorization server](oauth2-server.md) (`client_credentials`), to call
Kayra or another API **as the API itself**, not on behalf of a user. No
secret is shared with Kayra:

- **The app holds a key pair.** Kayra reads the public half from the app
  itself, at `/apis/<group>/<version>/-/jwks.json`, as it reads its
  [OpenAPI spec](../api-registrations.md#openapi-spec).
- **Or the app uses its platform's identity token,** a Kubernetes service
  account's say, as a [service account](federation.md) does.

The examples use [`infrapi-cli`](https://infrapi.github.io/cli/getting-started/#1-install)
against a Kayra at `https://kayra.example.com`, its authorization server on
(`oauth2.enabled`), and the `compute` project of `infrapi-cli app init
compute`. An app built on infrapi/lib does most of the work: see
[lib's identity package](https://infrapi.github.io/lib/packages/identity/).

## 1. Give the app a key

**infrapi-cli**

```bash
infrapi-cli app keygen /etc/compute/identity.pem > compute-jwks.json
```

`app keygen` writes an EC P-256 key, mode 0600, and prints its public half,
a JWK set whose `kid` is the key's RFC 7638 thumbprint. The app reads the key
from `INFRAPI_IDENTITY_KEY_PATH`:

```bash
INFRAPI_IDENTITY_KEY_PATH=/etc/compute/identity.pem
```

It then serves the public half, without authentication:

**curl**

```bash
curl -s https://gateway.example.com/apis/compute.infrapi.io/v1/-/jwks.json
# {"keys":[{"kty":"EC","crv":"P-256","x":"…","y":"…","kid":"hSO0YDfX…","use":"sig","alg":"ES256"}]}
```

The [dev stack](https://infrapi.github.io/cli/develop/dev-stack/) generates
a key for the API in `.infrapi-dev/keys/app-identity.pem` and sets
`INFRAPI_IDENTITY_KEY_PATH` in `.infrapi-dev/app.env`.

## 2. Register the API with its identity

`infrapi-cli app register` sends `"identity": {"jwks_from": "spec"}`.

**infrapi-cli**

```bash
infrapi-cli app register
```

**curl**

```bash
curl -s -X POST https://kayra.example.com/apis/catalog.infrapi.io/v1/apiregistrations \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "compute.infrapi.io", "short_name": "compute", "active": true, "owner": "compute-team",
       "identity": {"jwks_from": "spec"}}'
```

**OpenTofu/Terraform**

```hcl
resource "kayra_api_registration" "compute" {
  name       = "compute.infrapi.io"
  short_name = "compute"
  active     = true
  owner      = "compute-team"
  identity = {
    jwks_from = "spec"
  }
}
```

`identity` takes one of three forms:

| `identity` | The API proves it is the API with |
|---|---|
| `{"jwks_from": "spec"}` | a key whose public half it serves at `-/jwks.json`. The reconciler reads the keys with the spec, at each sync. |
| `{"jwks": {"keys": [...]}}` | a key whose public half is pinned in the registration. Nothing is fetched (`app register --jwks compute-jwks.json`). |
| `{"federated_credentials": [...]}` | its platform's identity token, matched as a [service account's](federation.md#2-add-a-federated-credential-to-the-service-account) is, from `federation.issuers` |

- **No identity** (`app register --no-identity`): the API gets no token.
- **No keys served** (a `404`, `401` or `403` at `-/jwks.json`, or an empty
  set: an app without a key, or on a lib before v0.20.0): the API gets no
  token, and its spec is still synced.
- **Refused (`400`):** a private key (a key with `d`: the contract's `JWK`
  allows no other member than a public key's), an empty identity, two forms
  at once, or an issuer that is not in `federation.issuers`.
- **`uid`:** Kayra sets it when the registration is first created, and
  keeps it when the registration is posted again. The API's tokens carry
  it, so a token of a deleted registration is refused, even after the API
  is registered again.

## 3. Get a token

The app asks Kayra's token endpoint, with an assertion signed by its key:
`iss` and `sub` are `system:api:compute.infrapi.io`, `aud` is the token
endpoint, `exp` is at most 5 minutes away, and its `jti` is used once.
infrapi/lib does it, and renews the token at 80% of its life:

```go
tokens, err := auth.NewClientCredentials(auth.ClientCredentialsOptions{
	Kayra: kayra, ClientID: identity.Subject("compute.infrapi.io"), Key: keys[0]})
network, err := client.NewClient(&client.ClientOptions{..., TokenSource: tokens.Token})
```

**curl**

```bash
curl -s -X POST https://kayra.example.com/oauth2/token \
  -d grant_type=client_credentials \
  -d client_id=system:api:compute.infrapi.io \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion="$ASSERTION"
# {"access_token":"eyJ…","token_type":"Bearer","expires_in":900}
```

Its identity:

**infrapi-cli**

```bash
infrapi-cli auth whoami
# client_id:  system:api:compute.infrapi.io
# groups:     system:apis
# kind:       api
# sub:        system:api:compute.infrapi.io
```

**curl**

```bash
curl -s https://kayra.example.com/oauth2/userinfo -H "Authorization: Bearer $API_TOKEN"
```

- **`resource`:** the token is for Kayra unless the request names other
  `resource`s, one of `oauth2.resources` or under one: the URL of an API
  it calls, `https://gateway.example.com/apis/network.infrapi.io/v1`.
- **Lifetime:** `oauth2.client_credentials_ttl`, 15 minutes by default, no
  refresh token.
- **Once the registration is deleted,** or registered without identity, its
  tokens are refused.

## 4. What it may do

**Without any grant,** an API may read its own registration and its
status, the sync state of every namespace subscribed to it:

**infrapi-cli**

```bash
infrapi-cli get apiregistrations compute.infrapi.io
infrapi-cli get apiregistrations/status compute.infrapi.io
```

**curl**

```bash
curl -s https://kayra.example.com/apis/catalog.infrapi.io/v1/apiregistrations/compute.infrapi.io/status \
  -H "Authorization: Bearer $API_TOKEN"
```

**OpenTofu/Terraform**

```hcl
data "kayra_api_registration" "compute" {
  name = "compute.infrapi.io"
}

data "kayra_api_registration_status" "compute" {
  name = "compute.infrapi.io"
}
```

Anything else is decided by the RBAC: a group that names the API in `apis`,
exactly, with no wildcard.

- **In a namespace group:** the API is a member of the namespace, with the
  rights its roles there grant, on the namespace's other APIs say.
- **In a cluster group:** the API has the rights of the cluster roles bound
  to it.

**infrapi-cli**

```bash
infrapi-cli create groups -n core -d '{"name": "apis",
  "metadata": {"namespace": "core", "region": "eu-west-1", "platform": "sandbox"},
  "apis": ["compute.infrapi.io"]}'
```

**curl**

```bash
curl -s -X POST https://kayra.example.com/apis/authorization.infrapi.io/v1/namespaces/core/groups \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "apis", "metadata": {"namespace": "core", "region": "eu-west-1", "platform": "sandbox"},
       "apis": ["compute.infrapi.io"]}'
```

**OpenTofu/Terraform**

```hcl
resource "kayra_group" "apis" {
  namespace = "core"
  name      = "apis"
  metadata = {
    namespace = "core"
    region    = "eu-west-1"
    platform  = "sandbox"
  }
  apis = ["compute.infrapi.io"]
}
```

Bind the group to a role as any other (see [RBAC & auth](rbac-and-auth.md#the-rbac-model)).
`system:api:` in `users` is refused: an API goes in `apis`.

## Rotating the key

With `jwks_from: spec`, Kayra holds the keys it read at the last sync. To
rotate without a gap:

1. **Serve both keys, the old one first** (it still signs):
   `INFRAPI_IDENTITY_KEY_PATH=/etc/compute/old.pem,/etc/compute/new.pem`.
   Then `infrapi-cli app register`: Kayra reads both.
2. **Serve the new key alone:** `INFRAPI_IDENTITY_KEY_PATH=/etc/compute/new.pem`,
   then `infrapi-cli app register` again. The old key is then refused.

With `jwks`, register the new set the same way, two keys, then one.

## On Kubernetes, without a key

An app whose platform gives it an identity token needs no key. List its
cluster in `federation.issuers`, mount a token projected for Kayra's
audience, and name it in the registration:

```json
{"identity": {"federated_credentials": [
  {"name": "k8s", "issuer": "https://kubernetes.default.svc.cluster.local",
   "subject": "system:serviceaccount:compute:compute-api"}]}}
```

The app sets `INFRAPI_IDENTITY_TOKEN_PATH` to the token's file instead of a
key. infrapi/lib reads it again for every token it asks.
