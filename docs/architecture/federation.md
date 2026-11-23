---
title: Federation
description: "A CI job or a workload logs in as a service account with its platform's own identity token, GitLab CI, GitHub Actions or Kubernetes: no secret stored anywhere."
weight: 24
---

# Federation

A CI job, or any workload whose platform issues it an OIDC identity token,
can log in as a [service account](service-accounts.md) **without a stored
secret**. Kayra trusts the platform's token as the service account when it
matches one of the account's **federated credentials**. It then issues the
account's own token for 15 minutes (`client_credentials`). Azure's workload
identity federation and GCP's work the same way.

The examples use [`infrapi-cli`](https://infrapi.github.io/cli/getting-started/#1-install)
and a Kayra at `https://kayra.example.com` with its
[authorization server](oauth2-server.md) on. They use the `core` namespace's
`deployer` service account, which already has its rights (see
[Service accounts](service-accounts.md#2-give-it-rights)).

## 1. Trust the platform (Kayra's admin)

Kayra's admin lists the issuers whose tokens may be trusted. A namespace's
admin can only pick among them, never add one, so an issuer is never
trusted, and Kayra never fetches its keys, without the admin's say.

```yaml
federation:
  issuers:
    - issuer: https://gitlab.example.com                      # a GitLab instance
    - issuer: https://token.actions.githubusercontent.com     # GitHub Actions
    - issuer: https://kubernetes.default.svc.cluster.local    # a cluster whose discovery Kayra cannot reach
      jwks_url: https://k8s.example.com/openid/v1/jwks
  proxy: http://proxy.example.com:3128                        # optional, as a remote provider's
```

- **Where the keys come from:** an issuer's keys are read from its OIDC
  discovery (`<issuer>/.well-known/openid-configuration`), or from
  `jwks_url` when that is set.
- **Caching:** the keys are kept 10 minutes. A key id Kayra does not hold
  makes it fetch them again, at most every 30 seconds.
- **Issuer URLs:** an issuer must be an `https` URL, or `http` on a loopback
  address.

## 2. Add a federated credential to the service account

**infrapi-cli**

```bash
infrapi-cli update serviceaccounts deployer -n core -d '{"federated_credentials": [
  {"name": "gitlab-main", "issuer": "https://gitlab.example.com",
   "subject": "project_path:infra/compute:ref_type:branch:ref:main"},
  {"name": "github-prod", "issuer": "https://token.actions.githubusercontent.com",
   "subject": "repo:example/compute:environment:prod"}]}'
```

**curl**

```bash
curl -s -X PUT https://kayra.example.com/apis/authorization.infrapi.io/v1/namespaces/core/serviceaccounts/deployer \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"federated_credentials": [
    {"name": "gitlab-main", "issuer": "https://gitlab.example.com",
     "subject": "project_path:infra/compute:ref_type:branch:ref:main"},
    {"name": "github-prod", "issuer": "https://token.actions.githubusercontent.com",
     "subject": "repo:example/compute:environment:prod"}]}'
```

A platform token is trusted when **all** of these hold for one credential:

| Field | |
|---|---|
| `name` | Unique within the service account. |
| `issuer` | The token's `iss`: one of `federation.issuers`, or the request gets a 400. |
| `subject` | The token's `sub`, exactly. |
| `claims` | Other claims, each exactly, a boolean as `"true"`: `{"project_path": "infra/compute", "ref_protected": "true"}`. |
| `audience` | What its `aud` must hold: Kayra's URL (its issuer) when empty. |

- **What a credential must name:** a `subject` or `claims`, or both, so that
  no credential trusts every token of an issuer.
- **No wildcard:** every value is compared exactly. To trust two branches,
  add two credentials.
- **The token must be valid:** signed by one of the issuer's keys, not
  expired.
- **Reuse:** a job may present the same token again until it expires. The
  platform hands it one token, not one per request.

> [!WARNING]
> A federated credential gives whoever holds a matching token the service
> account's rights. Match on the branch, the environment or the protected
> flag, never only on the project.

## 3. Log in from the job

`infrapi-cli auth login --service-account <namespace>/<name> --id-token
<source>` gets the job's token, asks Kayra for the service account's, and
saves it in a context. When that token expires, it asks for a new one the same
way, as long as the job's token is still valid.

| `--id-token` | Reads |
|---|---|
| `env:<NAME>` | the variable `<NAME>`: a GitLab CI `id_tokens` entry |
| `github` | GitHub Actions' token, asked for Kayra's URL as its audience |
| `file:<PATH>` | a file: a projected Kubernetes service account token |

### GitLab CI

The job asks for an `id_token` whose `aud` is Kayra's URL:

```yaml
deploy:
  id_tokens:
    KAYRA_ID_TOKEN:
      aud: https://kayra.example.com
  script:
    - infrapi-cli auth login --server https://kayra.example.com --service-account core/deployer --id-token env:KAYRA_ID_TOKEN
    - infrapi-cli update puppetreleases/promote apache -n core -d '{"location": "emea"}'
```

GitLab's `sub` is `project_path:<group>/<project>:ref_type:<branch|tag>:ref:<name>`.
Its other claims include `project_path`, `ref`, `ref_protected`,
`environment` and `namespace_path`.

### GitHub Actions

The job needs `id-token: write`:

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: prod
    permissions:
      id-token: write
      contents: read
    steps:
      - run: infrapi-cli auth login --server https://kayra.example.com --service-account core/deployer --id-token github
      - run: infrapi-cli get vms -n core
```

GitHub's `sub` is `repo:<owner>/<repo>:environment:<name>` in an environment.
Outside one it is `repo:<owner>/<repo>:ref:refs/heads/<branch>`. Its other
claims include `repository`, `ref`, `environment` and `workflow`.

### Kubernetes

A pod mounts a service account token projected for Kayra's audience. Its
cluster is in `federation.issuers`:

```yaml
volumes:
  - name: kayra-token
    projected:
      sources:
        - serviceAccountToken:
            audience: https://kayra.example.com
            path: token
            expirationSeconds: 3600
```

```bash
infrapi-cli auth login --server https://kayra.example.com --service-account core/deployer --id-token file:/var/run/secrets/kayra/token
```

Its `sub` is `system:serviceaccount:<k8s-namespace>:<name>`.

## Without infrapi-cli

**curl**

```bash
curl -s -X POST https://kayra.example.com/oauth2/token \
  -d grant_type=client_credentials \
  -d client_id=system:serviceaccount:core:deployer \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion="$KAYRA_ID_TOKEN" \
  -d resource=https://kayra.example.com
# {"access_token":"eyJ…","token_type":"Bearer","expires_in":900}
```

- **No refresh token:** ask again when the token expires.
- **`resource`:** one of `oauth2.resources`, or a URL under one, repeatable.
  It defaults to Kayra's own.
- **Lifetime:** the token lasts `oauth2.client_credentials_ttl`, 15 minutes
  by default.
- **A refusal** is an `invalid_client`, and its `error_description` says
  which check failed: the issuer, the signature, the expiry, or no matching
  credential (with the token's `sub` and `aud`).

## A key of its own instead (private_key_jwt)

A workload whose platform issues no identity can hold a key pair. Put the
public half in the service account's `jwks`; private keys are refused:

```bash
infrapi-cli update serviceaccounts deployer -n core -d '{"jwks": {"keys": [
  {"kty": "EC", "crv": "P-256", "kid": "deployer-1", "x": "…", "y": "…"}]}}'
```

Then sign an assertion with the private key: `iss` and `sub` the client id,
`aud` `https://kayra.example.com/oauth2/token`, an `exp` at most 5 minutes
away, and a `jti`. Send it as the `client_assertion` above. An assertion is
used once: the same `jti` is refused. The keys can be RSA or EC, signed with
RS*, PS* or ES*.
