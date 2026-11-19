---
title: "Authorization server"
description: Kayra's OAuth 2.1 authorization server, for infrapi-cli and MCP clients such as Claude, with tokens renewed and revoked.
weight: 25
---

# Authorization server

Kayra issues tokens of its own to a client — `infrapi-cli`, an MCP client
such as Claude, a script — and renews and revokes them: OAuth 2.1, as the
[MCP authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
asks of an authorization server. A human never logs in at Kayra: Kayra
sends them to a provider of theirs (Okta, GitLab...), every
`authentifications.<name>` with `remote.oauth2`, chosen on a page when there
are several. At its callback, Kayra checks the provider's OIDC ID token —
signed by its keys, its `iss` the provider's, its `aud` Kayra's
`client_id` there, its `nonce` the login's, not expired — then resolves the
user and their groups as for any token of that provider.

A provider without `remote.oauth2` is never offered: its tokens are only
checked when presented to an API, as a CI job's are, against its
[claims](../packages/config.md).

```text
client ──► Kayra /oauth2/authorize            (client, redirect URI, PKCE S256, resource)
       ──► the choice of a provider           when several have remote.oauth2
       ──► the provider                       the human logs in there, MFA included
       ──► Kayra /oauth2/callback             Kayra redeems the code with a PKCE of its own,
                                              checks the provider's ID token, resolves the user
       ──► the consent page                   a third-party client only
       ──► client redirect_uri?code=…&state=…&iss=…
client ──► Kayra POST /oauth2/token           code + code_verifier
       ◄── access token (a JWT, 15 min, aud the resource) + refresh token (opaque, rotated)
```

## Configure it

```yaml
authentifications:
  okta:                           # a provider to log in with: remote.oauth2
    remote:
      oauth2:
        client_id: 0oa1example    # Kayra's application there
        scopes: [openid, profile, email]   # openid always
        # at a login, the ID token's: the provider's user_id by default.
        # Okta's ID token's sub is its user id (00u...): its login is
        # preferred_username
        user_id: {from: token, field: preferred_username, filter: '^([^@]+)@'}
  gitlab:                         # no oauth2: a CI job's tokens, never a login
    remote:
      claims: {aud: api://infrapi-$region-$platform}

oauth2:
  enabled: true
  signer: self                    # the local provider whose issuer key signs: self by default
  access_token_ttl: 15m
  refresh_token_ttl: 720h         # a login's refresh tokens, renewed or not
  refresh_token_idle: 168h        # a refresh token unused
  resources:                      # what a token may be for: its aud; app.url by default
    - https://gateway.example.com
  clients:                        # declared clients
    - id: infrapi-cli
      redirect_uris: ["http://127.0.0.1/callback"]   # loopback: any port (RFC 8252)
      first_party: true                              # no consent page
  metadata_document_hosts:        # Client ID Metadata Documents: the hosts trusted
    - claude.ai
  dynamic_registration:           # RFC 7591, deprecated by MCP: off by default
    enabled: false
    hosts: []
```

Each provider to log in with redirects to `<app.url>/oauth2/callback`: add
it to Kayra's application there, with the `openid` scope.

## Clients

A client is one of:

- **declared**, in `oauth2.clients`: its redirect URIs matched exactly, a
  loopback one's port aside;
- **a Client ID Metadata Document**: its `client_id` an https URL with a
  path, on a host of `metadata_document_hosts`. Kayra fetches it (no
  redirect followed, 64 KiB at most), requires its `client_id` to be that
  URL, its `client_name` and `redirect_uris`, and keeps it an hour. No
  other host is fetched: the document's origin is the client's identity;
- **registered** at `/oauth2/register` (RFC 7591), when enabled, its
  redirect URIs loopback or on `dynamic_registration.hosts` only.

Clients are public: no secret, PKCE S256 and the refresh token's rotation
stand for it. A third-party client gets a consent page naming it, the host
it sends the user back to, the resource and the user.

## Tokens

- **The access token** is a JWT of the signer's key (`typ: at+jwt`): `iss`
  Kayra, `sub` the user, `aud` the resource (RFC 8707), `client_id`,
  `groups`, `jti`, `sid` its session, 15 minutes. Kayra checks it as any
  token of its own, and refuses it once its session is revoked.
- **The refresh token** is opaque, stored hashed. Each use rotates it; a
  refresh token used twice — stolen, or a client's stale copy — revokes its
  whole login. Each refresh resolves the user again in the directory: one
  gone gets no new token. Two uses of one refresh token at once, on two
  replicas, are taken one after the other (an etcd lock): the second is a
  reuse.

## Sessions

A session is a login: its refresh tokens, renewed one by one, and the
access tokens issued with them. A user lists theirs and revokes one, or all.
A revoked session's refresh token is refused, and its access tokens at once:
an app's routes ask Kayra's `/check`, which refuses them. Another user's
sessions take the cluster RBAC's `list` or `delete` on `sessions` of
`authorization.infrapi.io`, which the sysadmin has.

**infrapi-cli**

```bash
infrapi-cli auth sessions                        # yours, the current one marked *
infrapi-cli auth sessions revoke 1JkInLdoa2qUukggiHendg
infrapi-cli auth sessions revoke --all --user jdoe   # every one of jdoe's
```

**curl**

```bash
curl -s https://kayra.example.com/oauth2/sessions -H "Authorization: Bearer $TOKEN"
# [{"id":"1JkInLdoa2qUukggiHendg","user_id":"jdoe","client_id":"infrapi-cli",
#   "created_at":"…","last_used_at":"…","expires_at":"…"}]
curl -s -X DELETE https://kayra.example.com/oauth2/sessions/1JkInLdoa2qUukggiHendg -H "Authorization: Bearer $TOKEN"
curl -s -X DELETE "https://kayra.example.com/oauth2/sessions?user=jdoe" -H "Authorization: Bearer $TOKEN"
# {"revoked":2}
```

A session's `expires_at` is the earlier of `refresh_token_ttl` after its
login and `refresh_token_idle` after its last use.

## Endpoints

Every endpoint but the sessions' is unauthenticated: they are the login.

| Method | Path | |
|---|---|---|
| GET | `/.well-known/oauth-authorization-server` | RFC 8414 metadata: `code_challenge_methods_supported: [S256]`, `authorization_response_iss_parameter_supported`, `client_id_metadata_document_supported` |
| GET | `/oauth2/authorize` | `response_type=code`, `client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method=S256`, `state`, `resource` |
| GET | `/oauth2/login` | the provider chosen, when there are several |
| GET | `/oauth2/callback` | the provider's redirect |
| POST | `/oauth2/consent` | the consent page's form, bound to its browser by a cookie |
| POST | `/oauth2/token` | `grant_type=authorization_code` or `refresh_token` |
| POST | `/oauth2/revoke` | RFC 7009: a refresh token revokes its login, an access token its `jti` |
| POST | `/oauth2/register` | RFC 7591, when enabled |
| GET | `/oauth2/sessions` | a bearer token: the caller's sessions, `?user=` another's |
| DELETE | `/oauth2/sessions[/{id}]` | a bearer token: one session, or every one of the caller's, `?user=`'s |

Until the client and its redirect URI are known good, an error is shown,
never redirected to. After, the client gets it at its redirect URI, with
`state` and `iss`.

## Use it

`infrapi-cli auth login` runs this flow, renews the token before it
expires, and `auth logout` revokes its session. By hand, a client's token
exchange and its renewal:

**infrapi-cli**

```bash
infrapi-cli auth login --server https://kayra.example.com
infrapi-cli auth whoami    # the user the token is for
infrapi-cli auth logout
```

**curl**

```bash
# the code the client's redirect URI received, with its PKCE verifier
curl -s -X POST https://kayra.example.com/oauth2/token \
  -d grant_type=authorization_code -d code="$CODE" -d client_id=infrapi-cli \
  --data-urlencode redirect_uri=http://127.0.0.1:43210/callback -d code_verifier="$VERIFIER"
# {"access_token":"eyJ…","token_type":"Bearer","expires_in":900,"refresh_token":"…"}

curl -s -X POST https://kayra.example.com/oauth2/token \
  -d grant_type=refresh_token -d refresh_token="$REFRESH" -d client_id=infrapi-cli

curl -s -X POST https://kayra.example.com/oauth2/revoke -d token="$REFRESH" -d client_id=infrapi-cli
```
