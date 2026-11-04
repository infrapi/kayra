# crypto

```go
import "github.com/infrapi/kayra/internal/crypto"
```

The cryptographic concerns Kayra owns itself: the RSA keypair that
encrypts personal access token records at rest, loading the RSA signing
keys a `local:` authentication provider trusts, and minting the self-signed
bootstrap JWT.

## PAT keypair

```go
priv, err := crypto.LoadOrCreatePatKeypair(s, keys, cfg.Tokens.Pat)
```

Resolves the RSA keypair [tokenapi](tokenapi.md) encrypts every PAT record
under. When `cfg.PrivateKeyPath` names a file, that key is read directly;
otherwise a 2048-bit keypair is generated once and persisted in the store
at `keys.PatKeypair()`, so later starts reuse it instead of orphaning every
PAT issued so far.

## PAT records

```go
token, err := crypto.GenerateToken()        // "pat_" + 32 random bytes, base64url
crypto.IsToken(s)                           // has the "pat_" prefix?
hash := crypto.HashToken(token)             // sha256 hex — the etcd lookup key
```

```go
type PatRecord struct {
	UserID             string
	Authorization      string
	Provider           string
	CreatedAt          int64
	SnapshotGroups     []string          // only set for a claims-backed Authorization
	SnapshotAttributes map[string]string // only set for a claims-backed Authorization
}

data, err := crypto.EncryptRecord(pub, record)   // hybrid RSA-OAEP + AES-256-GCM
record, err := crypto.DecryptRecord(priv, data)
```

A record carries who the token belongs to and which
`authorizations.<name>` resolves it. For an `ldap`/`local` backend, roles
are always resolved live from the holder's current group membership at
request time — `SnapshotGroups`/`SnapshotAttributes` stay nil, nothing is
ever written there. The one exception is a `claims`-backed backend (see
[config](config.md#claims-no-directory-at-all)): it has no directory to
re-query later by bare user id, so [tokenapi](tokenapi.md) captures the
caller's own Groups/Attributes into these two fields at creation time
instead, and `middleware.resolvePAT` reads them back rather than
attempting a live lookup that has nowhere to go — the one case a PAT's
roles don't track a later change in group membership until the token is
regenerated. Encryption is hybrid: an AES-256 key seals the JSON
record (AES-GCM), and that AES key is itself wrapped with the RSA public
key (OAEP) — nobody holding only the etcd data, without the RSA private
key, can recover a record.

## Self-issued JWTs

```go
token, err := crypto.MintSelfJWT(key, subject, groups, ttl)
```

Signs a JWT (`RS256`/`RS384`/`RS512`, picked from `key.Algorithm`) embedding
`sub`, `groups`, `iat` and `exp` — `groups` must already be the caller's
real, resolved groups, never an operator-asserted claim. Whether those
embedded groups actually matter later depends on the consuming
`authorizations.<name>`: a `claims`-backed one with `from: token` reads
them straight back out of this JWT; an `ldap`/`local`-backed one ignores
them entirely and re-resolves live by `sub` instead (see
[middleware](middleware.md#authenticator)). `key` must have a private half
(`Issuer: true` in config); the `kid` header is set from `key.Kid` so
verification can locate the right key later.

## Local signing keys

```go
keys, err := crypto.LoadSigningKeys(provider.Local)
```

```go
type SigningKey struct {
	Kid       string
	Algorithm string
	Issuer    bool
	Expiry    int
	Audiences []string
	Private   *rsa.PrivateKey // non-nil only when the PEM held a private key
	Public    *rsa.PublicKey
}
```

Decodes every entry of an `authentifications.<name>.local` list. Each
entry's `secret` is a PEM block — `RSA PRIVATE KEY` (PKCS1), `PRIVATE KEY`
(PKCS8) or `PUBLIC KEY` — so a provider can trust a key it never signs
with (public-only) alongside ones it does (private). Disabled entries
(`enabled: false`) are skipped entirely.
