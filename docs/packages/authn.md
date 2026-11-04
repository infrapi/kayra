# authn

```go
import "github.com/infrapi/kayra/internal/authn"
```

Validates an incoming bearer JWT, resolves the user id it identifies, and
— for a `claims`-backed `authorizations.<name>` entry only — the groups
and attributes too, straight out of that same already-verified token:
the steps between "a request carries an `Authorization: Bearer ...`
header" and "this is `jdoe`, authenticated via `okta`, member of
`sandbox-core-sysadmin`."

## Verify

```go
v, err := authn.Verify(manager, tokenString)
```

```go
type Verified struct {
	Provider string
	Claims   jwt.MapClaims
	Token    string
}
```

Parses the token, reads its `kid` header, and locates the owning provider
and public key via [`oidc.Manager.FindKey`](oidc.md#manager) — so a bad or
unknown `kid` fails before any signature check runs. Only `RS256`/`RS384`/
`RS512` are accepted. Beyond signature validity, two checks the JWT library
doesn't do on its own: `iat` must not be in the future, `exp` (if present)
must not be in the past — the spec's "obviously then token must contain
'iat' and can't be in future, and 'exp' can't be expired."

```go
ttl := v.ExpiresIn(fallback)
```

Returns the duration until `exp`, or `fallback` when the token carries none
or it's already non-positive — this is the TTL
[`authz.Cached.ResolveUser`](authz.md#cached) caches the resolved user
under, per the spec's "cache ... for 'exp' duration."

## ResolveUserID

```go
userID, err := authn.ResolveUserID(v, cfg, remoteURL, proxy)
```

`cfg` is a provider's `remote.user_id` block
([config.UserIDConfig](config.md#authentifications)); `remoteURL`/`proxy`
are that same provider's `remote.url`/`remote.proxy`:

- `from: "token"` — reads `cfg.Field` directly out of `v.Claims`;
  `remoteURL`/`proxy` go unused.
- `from: "userinfo_endpoint"` — fetches the provider's discovery document
  to find `userinfo_endpoint` (through `proxy`, if set — see
  [oidc.ClientFor](oidc.md#clientfor)), calls it with the bearer token,
  and reads `cfg.Field` out of the JSON response.

Either way, `cfg.Filter` (if set) is a regexp applied to the raw value,
first capture group wins — e.g. `^([^@]+)@` to turn `jdoe@company.com`
into `jdoe`.

## ResolveGroups

```go
groups, err := authn.ResolveGroups(v, from, field, filter, remoteURL, proxy)
```

`from`/`field`/`remoteURL`/`proxy` are the exact same sources
`ResolveUserID` reads from (a token claim, or the provider's userinfo
response) — just applied to a list claim instead of a scalar one, for
an `authorizations.<name>.claims` entry's `from`/`groups_field`
([config.ClaimsAuthzConfig](config.md#claims-no-directory-at-all)).
`field` must hold a JSON array of strings (e.g. Okta's own `MemberOf`).
`filter`, when set, is applied independently to each element exactly
like `authorizations.<name>.ldap.user.groups.member_regex` does to a
real `memberOf` value: an element that doesn't match is dropped, one
that does contributes its first capture group (or the whole match,
when `filter` has no capture group) to the result. When
`from: "userinfo_endpoint"`, `v` caches the fetched response on first
use (`Verified.fetchUserinfo`), so calling this after `ResolveUserID`
(or `ResolveAttributes`) for the same token costs no extra network
call — the identical response already fetched is just read again for
this field.

## ResolveAttributes

```go
attrs, err := authn.ResolveAttributes(v, from, userAttributes, remoteURL, proxy)
```

`ResolveGroups`' sibling for the attributes half of a `claims` entry:
`userAttributes` is the same local-name -> field mapping
`authorizations.<name>.ldap.user.user_attributes` uses
(`config.ClaimsAuthzConfig.UserAttributes`), read from the same
`from`/`remoteURL`/`proxy` source. A named field absent from the source, or
not a string, resolves to `""` rather than failing the whole
resolution or omitting the key — exactly how a missing LDAP attribute
already behaves, so a caller never has to treat the two backends
differently.
