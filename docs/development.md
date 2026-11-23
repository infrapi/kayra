---
title: Development
description: Build, test and documentation workflow for the Kayra repository, and its source layout.
weight: 60
---

# Development

## Quality gate

```bash
go build ./...
go vet ./...
go test ./...
```

or, with the Makefile:

```bash
make all
```

| Target | Command |
|--------|---------|
| `setup` | installs `golangci-lint`, `gosec` and `goreleaser` if missing |
| `tidy` | `go mod tidy` |
| `fmt` | `gofmt -w` on every tracked Go file |
| `lint` | `golangci-lint run` |
| `security` | `gosec -exclude-dir _local -quiet ./...` |
| `test` | `go test` with coverage, writes `cover.out` and `coverage.html` |
| `docs` | previews these pages in the InfraPI portal, see below |

## Documentation

These pages are published by the InfraPI developer portal,
[infrapi/docs](https://github.com/infrapi/docs): a Hugo site that pulls
`docs/` from every product at build time. There is no site to build in this
repository. To preview a change, clone infrapi/docs next to this repository,
then:

```bash
make docs                  # make -C ../docs dev: links your checkouts, serves http://localhost:1313/docs/ with live reload
make -C ../docs check      # builds as the portal's CI does: fails on any broken link or anchor
```

The portal needs Hugo v0.158 or later (`make -C ../docs install-hugo`
installs it with `go install`).

There is no navigation file: the portal builds the menu from the folders,
and orders the pages within a folder by their `weight`. A new page is a new
file with its front matter.

Every page is portable, GitHub-native Markdown: it starts with YAML front
matter (`title`, `description`, `weight` — the page's order inside its
folder), keeps its own H1, and uses GitHub alerts
(`> [!NOTE]`), `<details>` blocks and plain labelled code blocks rather
than site-specific shortcodes, admonitions or snippet includes, so the
same file renders on github.com and in the portal.

Every example of a call to Kayra's API is given twice: a `**infrapi-cli**`
paragraph followed by its code block, then a `**curl**` paragraph followed
by the same requests. github.com shows them one after the other; the
developer portal renders consecutive labelled code blocks as tabs. Things
only one of them can do (`kayra token mint`, `infrapi-cli auth context set`)
stay a single block.

`docs/index.md` is a real page — the docs entry point, with the "where to
start" table and the package table — not an include of the README.
`README.md` is the repository's front door (what Kayra is, the binary
and its client, core concepts, license) and links into `docs/` with relative
paths (`docs/getting-started.md`, `docs/packages/config.md`, ...).
Links between docs pages are relative `.md` paths too, with GitHub-style
heading anchors. Links to another InfraPI repository's docs stay
absolute (`https://infrapi.github.io/<repo>/...`).

A push to `main` that changes `docs/` runs `.github/workflows/notify-docs.yml`,
which asks the portal to rebuild, and so does every release; the portal also
rebuilds every night. There is no manual deploy step.

## Layout

```text
cmd/kayra          app management: serve, reconciler, cache clean — always reads kayra.yaml
internal/config      kayra.yaml loading and validation
internal/store       etcd/local key-value abstraction, Watch
internal/crypto      PAT keypair, PAT encryption, self-signing keys, self-JWT
internal/oidc        discovery/JWKS fetch+cache, Kayra's own discovery endpoint
internal/discovery   /.well-known/kayra.json, what infrapi/lib and infrapi-cli discover
internal/authn       bearer token verification, user id resolution
internal/authz       LDAP/dev-local directory resolution, resolved-user cache
internal/oauth2server the authorization server: tokens of Kayra's own, for infrapi-cli and MCP clients
internal/middleware  gin Authenticator
internal/rbac        cluster/namespace groups, roles, rolebindings
internal/catalog     api registrations, namespaces, subscriptions, Reconciler
internal/tokenapi    personal access token issuance
internal/httpapi     RFC 9457 error response helper
internal/apiserver   wires every other package onto one gin engine
docs/                this site
specs/                the full functional spec
```

Package-by-domain, not package-by-layer: each of these owns its own types,
etcd persistence and HTTP handlers together, rather than a shared
`models`/`controllers` split. Tests sit next to the code they cover and use
a real `LocalStore` rather than mocks.
