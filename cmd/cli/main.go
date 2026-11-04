// Command cli is the portable, end-user Kayra client: everything it
// does talks to a Kayra server's own API, never to local code or
// config — unlike cmd/kayra, which runs and manages the server
// itself (serve, reconciler, cache). This is the one binary meant to
// hand to someone who has nothing but a server URL: `kayra` (the
// server binary) always ships alongside kayra.yaml and the backends
// it configures; this one never does.
package main

import (
	"cmp"
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/infrapi/kayra/internal/clicontext"
	"github.com/infrapi/kayra/internal/oauth2login"
)

func main() {
	root := &cli.Command{
		Name:  "kayra-cli",
		Usage: "the portable Kayra client — log in and manage saved logins against any Kayra server's own API",
		Commands: []*cli.Command{
			loginCommand(),
			contextCommand(),
		},
		CommandNotFound: func(ctx context.Context, cmd *cli.Command, name string) {
			fmt.Fprintf(os.Stderr, "kayra-cli: unknown command %q\n\n", name)
			_ = cli.ShowAppHelp(cmd)
			os.Exit(2)
		},
	}

	if err := root.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "kayra-cli:", err)
		os.Exit(1)
	}
}

// contextNameSanitizer collapses anything that isn't a lowercase
// letter, digit, underscore or dot into a single '-' — keeps a
// server-derived context name readable (and shell/YAML-key-safe)
// without needing a real slug library for what's really just a host.
var contextNameSanitizer = regexp.MustCompile(`[^a-z0-9_.]+`)

// sanitizeContextName derives `login`'s default --context-name from
// --server: its host[:port] (dropping scheme and path — the part that
// actually tells two servers apart), lowercased and sanitized. Falls
// back to "default" for a URL with no host at all.
func sanitizeContextName(server string) string {
	name := server
	if u, err := url.Parse(server); err == nil && u.Host != "" {
		name = u.Host
	}
	name = contextNameSanitizer.ReplaceAllString(strings.ToLower(name), "-")
	name = strings.Trim(name, "-")
	if name == "" {
		return "default"
	}
	return name
}

// loginCommand is this CLI's entry point — the one and only way to
// authenticate: a browser-based OAuth2 login against --server's own
// API. It never reads local config and never names a provider; see
// internal/oauth2login.LoginToServer and internal/oauth2broker for
// how the server resolves one on its own.
func loginCommand() *cli.Command {
	return &cli.Command{
		Name:  "login",
		Usage: "log in to a Kayra server via its own browser-based OAuth2 flow — never reads local config",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "server", Required: true, Usage: "Kayra server base URL, e.g. https://kayra.example.com"},
			&cli.StringFlag{Name: "context-name", Usage: "name to save this login under (defaults to the sanitized --server host)"},
			&cli.DurationFlag{Name: "timeout", Value: 2 * time.Minute, Usage: "how long to wait for the browser round trip before giving up"},
		},
		Action: runLogin,
	}
}

func runLogin(ctx context.Context, cmd *cli.Command) error {
	server := cmd.String("server")

	loginCtx, cancel := context.WithTimeout(ctx, cmd.Duration("timeout"))
	defer cancel()

	result, err := oauth2login.LoginToServer(loginCtx, server, os.Stderr)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}

	name := cmp.Or(cmd.String("context-name"), sanitizeContextName(server))
	f, err := clicontext.Load()
	if err != nil {
		return err
	}
	f.SetContext(name, clicontext.Context{
		Server:    server,
		Token:     result.AccessToken,
		TokenType: result.TokenType,
		Expiry:    result.Expiry,
	})
	if err := f.Save(); err != nil {
		return err
	}

	path, err := clicontext.Path()
	if err != nil {
		return err
	}
	// The token itself is deliberately never printed here — it's
	// sitting in the context file this just wrote, retrievable any
	// time via `context token`, which is the one place it should have
	// to be read back from.
	fmt.Fprintf(os.Stderr, "kayra-cli: logged in — saved context %q to %s (now current)\n", name, path)
	fmt.Println("kayra-cli: run `kayra-cli context token` to print the bearer token")
	return nil
}

// contextCommand manages ~/.config/kayra/config — the kubeconfig-style
// current-context/contexts file `login` writes to (see
// internal/clicontext), so a saved login can be listed, switched back
// to, or retrieved again without logging in a second time.
func contextCommand() *cli.Command {
	return &cli.Command{
		Name:  "context",
		Usage: "manage saved logins in ~/.config/kayra/config",
		Commands: []*cli.Command{
			{
				Name:   "list",
				Usage:  "list saved contexts, marking the current one",
				Action: runContextList,
			},
			{
				Name:   "current",
				Usage:  "show the current context's name and details",
				Action: runContextCurrent,
			},
			{
				Name:      "use",
				Usage:     "switch the current context",
				ArgsUsage: "<name>",
				Action:    runContextUse,
			},
			{
				Name:      "delete",
				Usage:     "delete a saved context",
				ArgsUsage: "<name>",
				Action:    runContextDelete,
			},
			{
				Name:      "token",
				Usage:     "print a context's bearer token (defaults to the current context)",
				ArgsUsage: "[name]",
				Action:    runContextToken,
			},
		},
	}
}

func runContextList(ctx context.Context, cmd *cli.Command) error {
	f, err := clicontext.Load()
	if err != nil {
		return err
	}
	if len(f.Contexts) == 0 {
		fmt.Println("kayra-cli: no saved contexts — run `kayra-cli login --server <url>`")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "CURRENT\tNAME\tPROVIDER\tSERVER\tEXPIRY")
	for _, name := range f.Names() {
		c := f.Contexts[name]
		current := ""
		if name == f.CurrentContext {
			current = "*"
		}
		expiry := "-"
		if !c.Expiry.IsZero() {
			expiry = c.Expiry.Local().Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", current, name, c.Provider, c.Server, expiry)
	}
	return w.Flush()
}

func runContextCurrent(ctx context.Context, cmd *cli.Command) error {
	f, err := clicontext.Load()
	if err != nil {
		return err
	}
	name, c, err := f.Current()
	if err != nil {
		return err
	}

	fmt.Printf("name:     %s\nprovider: %s\nserver:   %s\n", name, c.Provider, c.Server)
	if c.Username != "" {
		fmt.Printf("username: %s\n", c.Username)
	}
	if !c.Expiry.IsZero() {
		fmt.Printf("expiry:   %s\n", c.Expiry.Local().Format(time.RFC3339))
	}
	return nil
}

func runContextUse(ctx context.Context, cmd *cli.Command) error {
	name := cmd.Args().First()
	if name == "" {
		return fmt.Errorf("context: usage: kayra-cli context use <name>")
	}

	f, err := clicontext.Load()
	if err != nil {
		return err
	}
	if err := f.Use(name); err != nil {
		return err
	}
	if err := f.Save(); err != nil {
		return err
	}

	fmt.Printf("kayra-cli: switched to context %q\n", name)
	return nil
}

func runContextDelete(ctx context.Context, cmd *cli.Command) error {
	name := cmd.Args().First()
	if name == "" {
		return fmt.Errorf("context: usage: kayra-cli context delete <name>")
	}

	f, err := clicontext.Load()
	if err != nil {
		return err
	}
	if err := f.Delete(name); err != nil {
		return err
	}
	if err := f.Save(); err != nil {
		return err
	}

	fmt.Printf("kayra-cli: deleted context %q\n", name)
	return nil
}

func runContextToken(ctx context.Context, cmd *cli.Command) error {
	f, err := clicontext.Load()
	if err != nil {
		return err
	}

	if name := cmd.Args().First(); name != "" {
		c, ok := f.Contexts[name]
		if !ok {
			return fmt.Errorf("context: no such context %q", name)
		}
		fmt.Println(c.Token)
		return nil
	}

	_, c, err := f.Current()
	if err != nil {
		return err
	}
	fmt.Println(c.Token)
	return nil
}
