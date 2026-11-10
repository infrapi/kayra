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
| `build` | `go build ./...` |
| `vet` | `go vet ./...` |
| `fmt` | `gofmt -w` on every tracked Go file |
| `test` | `go test` with coverage, writes `cover.out` and `coverage.html` |
| `docs` | `mkdocs build` into `site/` |
| `docs-serve` | `mkdocs serve`, live reload on `http://localhost:8000` |

## Documentation

The site is MkDocs Material, same toolchain and theme as
[infrapi/lib](https://infrapi.github.io/lib/). Install it once:

```bash
pip install mkdocs mkdocs-material pymdown-extensions mkdocs-git-revision-date-localized-plugin
```

Then:

```bash
make docs         # build into site/
make docs-serve   # live reload on http://localhost:8000
```

Pages live in `docs/` and the navigation is declared in `mkdocs.yml`. A new
page must be added to `nav:`, otherwise the CI build — which runs `mkdocs
build --strict` — fails.

Every page is portable, GitHub-native Markdown: it starts with YAML front
matter (`title`, `description`, `weight` — the page's order inside its
folder, matching `nav:`), keeps its own H1, and uses GitHub alerts
(`> [!NOTE]`), `<details>` blocks and plain labelled code blocks rather
than MkDocs-only admonitions, content tabs or snippet includes, so the
same file renders on github.com, on this site and in the InfraPI
developer portal.

`docs/index.md` is a real page — the docs entry point, with the "where to
start" table and the package table — not an include of the README.
`README.md` is the repository's front door (what Kayra is, the two
binaries, core concepts, license) and links into `docs/` with relative
paths (`docs/getting-started.md`, `docs/packages/config.md`, ...).
Links between docs pages are relative `.md` paths too, with GitHub-style
heading anchors. Links to another InfraPI repository's docs stay
absolute (`https://infrapi.github.io/<repo>/...`).

`.github/workflows/docs.yml` builds the site on every push and PR, and on
`main` also publishes it through GitHub Pages (Settings > Pages > Source =
"GitHub Actions"). There is no manual deploy step.

## Layout

```text
cmd/kayra          app management: serve, reconciler, cache clean — always reads kayra.yaml
cmd/cli              the portable end-user client: login, context — never reads local config
internal/config      kayra.yaml loading and validation
internal/store       etcd/local key-value abstraction, Watch
internal/crypto      PAT keypair, PAT encryption, self-signing keys, self-JWT
internal/oidc        discovery/JWKS fetch+cache, Kayra's own discovery endpoint
internal/authn       bearer token verification, user id resolution
internal/authz       LDAP/dev-local directory resolution, resolved-user cache
internal/oauth2broker server-side relay for kayra-cli login's browser-based OAuth2 flow
internal/oauth2login  the CLI-side half of that same flow (cmd/cli only)
internal/clicontext  cmd/cli's own ~/.config/kayra/config (kubeconfig-style contexts)
internal/middleware  gin Authenticator and SysadminGate
internal/rbac        cluster/namespace groups, roles, rolebindings
internal/catalog     api registrations, namespaces (tenants), subscriptions, Reconciler
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
