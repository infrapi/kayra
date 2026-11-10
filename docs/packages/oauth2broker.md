---
title: oauth2broker
description: Server-side relay that lets kayra-cli login run a browser-based OAuth2 flow without local config.
weight: 90
---

# oauth2broker

```go
import "github.com/infrapi/kayra/internal/oauth2broker"
```

Lets [`kayra-cli login`](../cli.md#login) (cmd/cli — the portable,
end-user client, running on someone's laptop with no local config of
its own) complete a browser-based OAuth2 Authorization Code + PKCE
login against a provider that will never allowlist a loopback
redirect_uri — most enterprise IdPs, Okta included, refuse to register
`http://127.0.0.1:PORT/callback` for security policy reasons. Kayra's
own public URL is the one address the provider *does* allowlist, so
Kayra stands in as a pure relay — the same role OpenShift's own OAuth
server plays in front of its configured identity providers for
`oc login`.

The CLI's own PKCE challenge/state/redirect_uri pass straight through
unchanged; Kayra never sees the verifier and never requests (or
needs) its own client secret — the provider's real `client_id` stays
the exact same public, PKCE-only registration
`authentifications.<name>.remote.oauth2` already configures. Only the
`redirect_uri` the provider itself sees changes: Kayra's own
`/oauth2/v1/callback` instead of a loopback address.

The CLI never names a provider at all — see
[Provider resolution](#provider-resolution) below — and never reads local
config, so `/callback` additionally relays the chosen provider's own
public `token_endpoint`/`client_id` back to it: everything
[`oauth2login.LoginToServer`](oauth2login.md#logintoserver) needs to
finish the PKCE exchange itself, with zero prior knowledge of the
provider. Kayra could never do that exchange on the CLI's behalf
either way — the `code_verifier` backing `code_challenge` never leaves
the CLI process.

## RegisterRoutes

```go
oauth2broker.RegisterRoutes(engine, cfg, store, keys, baseURL)
```

`baseURL` is this instance's own resolved `app.url` — the exact value
[`oidc.RegisterRoutes`](oidc.md#kayras-own-endpoints) is given too,
never `cfg.App.URL`'s raw YAML value directly, so both land on the one
address a provider's app registration actually allowlists. Mounts
three routes, all unauthenticated by design — this *is* the login
flow, the same way `oidc.RegisterRoutes`' discovery endpoints are:

- **`GET /oauth2/v1/authorize`** — resolves which
  `authentifications.<name>` to use (the CLI's query carries
  `redirect_uri`, `state`, `code_challenge`, `code_challenge_method`
  — must be `S256` — but never a provider), then renders a one-button
  confirmation page ("Continue with `<provider>`") — deliberately no
  username/password fallback: the only way through this page is onward
  to the provider's own real login. Resolution: straight through when
  exactly one `remote.oauth2` provider is configured, or a **chooser
  page** listing every one of them when there's more than one — each
  option there links straight to `/authorize/continue` (see below),
  never back through this confirmation page, since picking one off the
  chooser already *is* the deliberate click the confirmation page
  otherwise exists to collect. Zero configured providers fails with
  `502`.
- **`GET /oauth2/v1/authorize/continue`** — the confirmation (or
  chooser) page's own link, carrying the resolved `provider` plus the
  rest of the query forward. Stashes the CLI's `redirect_uri`/`state`,
  plus the chosen provider's own `token_endpoint`
  ([`oidc.FetchDiscovery`](oidc.md#discoveryjwks-fetch)) and `client_id`,
  in the store (`keys.OAuth2BrokerState`, 10-minute TTL, one-time use)
  under a freshly generated id, then `302`s the browser on to the
  provider's **real** `authorization_endpoint` with: the provider's own
  `client_id`/`scopes` (`authorizations.<name>.remote.oauth2`, scopes
  falling back to [`oauth2login.DefaultScopes`](oauth2login.md)),
  Kayra's own callback as `redirect_uri`, that fresh id as `state`,
  and the CLI's `code_challenge` passed through unchanged.
- **`GET /oauth2/v1/callback`** — the provider's own redirect target.
  Looks up the stashed record by `state` (deleting it either way — one
  shot), then `302`s the browser the rest of the way to the CLI's own
  local listener with the provider's `code` (or `error`/
  `error_description`), the CLI's own original `state`, and — only
  alongside a successful `code` — the stashed `token_endpoint`/
  `client_id` too, since `oauth2login.LoginToServer` has no other way
  to learn them. Otherwise indistinguishable, from `oauth2login`'s own
  callback handler's perspective, from the provider having redirected
  there directly.

## Provider resolution

`authorizeParams.Provider` is never trusted from the incoming
`/authorize` request — `configuredOAuth2Providers` (every
`authentifications.<name>` with `remote.oauth2` set, sorted) is always
consulted instead:

```go
switch names := configuredOAuth2Providers(cfg); len(names) {
case 0:
	// 502 — nothing to log in against
case 1:
	p.Provider = names[0] // auto-resolved, straight to the confirmation page
default:
	renderProviderChooser(c, p, names) // one click per option, no second confirm
}
```

By the time `/authorize/continue` parses the same `authorizeParams`
struct off its own query string, `provider` is always present and
always one Kayra itself put there — `providerOAuth2Config` still
validates it there regardless, as defense in depth against a tampered
continue link.

## The open-redirect guard

`redirect_uri` is checked (RFC 8252 §7.3) before anything else is
stored or redirected to: it must be `http://127.0.0.1:.../...` or
`http://[::1]:.../...` — a loopback **IP literal**, never a hostname
(DNS can be hijacked) and never an arbitrary external URL. Without
this, a crafted
`/oauth2/v1/authorize?...&redirect_uri=https://evil.example` link
would walk a victim through a genuine provider login and then hand the
resulting authorization code to `evil.example` instead of the real
CLI. Checked once at `/authorize`/`/authorize/continue` (so a bad link
fails before ever reaching the provider) and re-checked at `/callback`
before the final redirect (defense in depth — nothing on that path
should ever be able to redirect anywhere else).

The one other accepted value is the exact string
`urn:ietf:wg:oauth:2.0:oob` (`oauth2login.OOBRedirectURI`, sent by
`kayra-cli login --no-browser`). It redirects nowhere, so it can't be
abused as an open redirect: at `/callback` the broker instead renders the
`oauth2login.LoginCode` the loopback redirect would have carried (code,
the CLI's own state, token endpoint, client ID, `api_domain`), as one
base64url string for the user to paste into their terminal. The page is
sent `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. The
code is only redeemable with the verifier the originating CLI holds
(PKCE), and that CLI refuses any code whose state isn't its own. The page
still warns users to paste it only into a terminal where they started the
login themselves, since a phished user who hands their code to whoever
sent them the link is the one remaining risk, as with any device or
out-of-band flow.

## Confirmation and chooser pages

Every value reflected into either page's HTML — the provider name(s),
each link's full query string — is `html.EscapeString`'d first, even
though `provider` is always a real configured `authentifications.<name>`
by the time it's rendered: the link embeds attacker-influenced input
(`state`, `code_challenge`) verbatim otherwise.

Exercised end-to-end in tests via a double that acts like an actual
browser: fetch whichever page `/authorize` serves back, pull the first
button's `href` out of the returned HTML (unescaping the HTML entities
a real browser's parser would) and follow it — repeating that for as
many hops as the response has (one when a single provider auto-resolved,
one more when a chooser page was in the way) — against a fake provider
that itself checks the received `code_verifier` genuinely hashes (S256)
to the `code_challenge` it was sent, and that the final token exchange's
`redirect_uri` is Kayra's own callback, never the CLI's loopback.
