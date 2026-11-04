# clicontext

```go
import "github.com/infrapi/kayra/internal/clicontext"
```

Persists `cmd/cli`'s own login state to `~/.config/kayra/config` — which
server a token belongs to, and the token itself — in the same
current-context/contexts shape `kubectl` keeps in `~/.kube/config`.
[`kayra-cli login`](../cli.md#login) writes to it on every successful
login; [`kayra-cli context`](../cli.md#context) reads and switches it.

```go
f, err := clicontext.Load()               // reads Path(), or an empty File if it doesn't exist yet

f.SetContext("kayra-internal", clicontext.Context{
	Server:    server,
	Token:     result.AccessToken,
	TokenType: result.TokenType,
	Expiry:    result.Expiry,
})                                         // upserts and switches CurrentContext to it

err = f.Save()                             // writes back to Path(), dir 0700 / file 0600

name, ctx, err := f.Current()              // errors if nothing has ever logged in
err = f.Use("self")                        // switch without touching credentials
err = f.Delete("self")                     // drop a saved context
names := f.Names()                         // sorted, for stable `context list` output
```

`Path()` resolves `$KAYRA_CONTEXT_FILE` first, then
`$XDG_CONFIG_HOME/kayra/config`, then `~/.config/kayra/config` — not to
be confused with `$KAYRA_CONFIG_FILE`/`--config`, which names the
**server's** `kayra.yaml`. The file holds bearer tokens, so `Save`
creates its parent directory at `0700` and writes the file itself at
`0600`.
