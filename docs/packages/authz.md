# authz

```go
import "github.com/infrapi/kayra/internal/authz"
```

Resolves a user id to their directory attributes and group membership,
against either a real LDAP directory or the `dev: local:` fixture the spec
calls out for testing without one, and caches the result.

## Authorizer

```go
type UserInfo struct {
	ID         string
	Attributes map[string]string
	Groups     []string
}

type Authorizer interface {
	ResolveUser(userID string) (UserInfo, error)
}
```

Every `authorizations.<name>` entry's full contract. Authorization
decisions elsewhere (see [rbac.CanManageNamespaceRBAC](rbac.md#canmanagenamespacerbac))
are made against the groups a caller's own token already carries, never
against a separately synced member list — so resolving a *group's*
membership independently of a user is deliberately not part of this
package's job.

```go
authorizer, err := authz.New(cfg) // cfg: config.AuthorizationBackend
```

Picks `LDAPAuthorizer` or `DevLocalAuthorizer` depending on which of
`cfg.Ldap`/`cfg.Local` is set.

```go
type PasswordAuthenticator interface {
	Login(username, password string) (UserInfo, error)
}
```

Both backends implement this too: verify a username/password against the
real backend, return the same `UserInfo` `ResolveUser` would — the
password-bind half of [`crypto.MintSelfJWT`](crypto.md#self-issued-jwts),
minting a self-issued JWT from a real login instead of trusting whatever
groups an operator types in. There is no CLI command built on this
anymore (see [CLI](../cli.md)); it remains a library-level capability for
whatever bootstraps a self-signed credential.

## LDAPAuthorizer

Dials per operation rather than holding a long-lived connection (LDAP
lookups are infrequent — the result is cached — so there's no idle
connection to babysit). `Login` does the standard "search then bind":
locate the user's entry with the service account, then re-bind the same
connection as that entry's DN with the submitted password.

`member_regex` filters the raw `memberOf`-style DN list down to the groups
Kayra cares about: a DN that doesn't match is dropped, one that does
contributes its first capture group (or the whole match, with no capture
group) as the resolved group name. `options.lowercase_usernames` and
`allow_username_or_email_login` normalize the submitted id before
searching; `retry_empty_result_with_codes` retries a search that comes
back empty with one of those LDAP result codes.

## DevLocalAuthorizer

Reads a YAML fixture (`examples/kayra-users.yaml` is a real one) standing
in for that same directory:

```yaml
users:
  - id: jdoe
    password: "s3cret" # dev/test only, plaintext
    attributes:
      email: jdoe@example.com
    groups:
      - "cn=sandbox-core-sysadmin,cn=groups,cn=accounts,dc=example,dc=com"
```

The same optional `member_regex` applies, with identical semantics to the
real LDAP backend — so a fixture authored with raw DN-shaped strings
exercises the same filtering a real directory would.

## Cached

```go
cached := authz.NewCached(backend, s, keys, name)
info, err := cached.ResolveUser(userID, ttl)
```

Wraps any `Authorizer` with the store-backed cache the spec describes:
"cache user's info for 'exp' duration ... to avoid multiple LDAP calls
during a session." Scoped by `name` (the owning `authorizations.<name>`),
so two providers resolving the same user id never collide. See
[`kayra cache clean --scope users`](../cli.md#cache-clean).
