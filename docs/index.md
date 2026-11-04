# kayra

Authentication, namespace creation and IAM policy service, built on
[`infrapi/lib`](https://infrapi.github.io/lib/).

Three resources — cluster-wide **stacks**, per-tenant **namespaces**, and
the **subscriptions** linking them — sit behind the same bearer-auth and
cluster-RBAC model every other endpoint uses, with a separate `kayra
reconciler` process turning disabled records active.

!!! note "Looking for the GitHub README?"
    This site mirrors it in more digestible pieces — start with
    [Getting started](getting-started.md) or jump straight to a topic
    below. The source of truth for both is `docs/` + `README.md` in the
    repository.

## Where to start

| I want to... | Go to |
|---|---|
| Run Kayra for the first time | [Getting started](getting-started.md) |
| Understand how the pieces fit together | [Architecture overview](architecture/overview.md) |
| See who can authenticate and who can manage what | [RBAC & auth](architecture/rbac-and-auth.md) |
| Create or update a stack | [Stacks](architecture/stacks.md) |
| Create or update a tenant | [Namespaces](architecture/namespaces.md) |
| Subscribe a tenant to a stack, or trigger reconcile | [Subscriptions & reconciliation](architecture/subscriptions.md) |
| Run a command (`serve`, `reconciler`, `cache clean`, `token mint`) or log in (`kayra-cli login`) | [CLI](cli.md) |
| Look up one `internal/*` package's API | [Packages](packages/apiserver.md) |
| Build, test, or work on the docs themselves | [Development](development.md) |
