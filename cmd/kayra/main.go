// Command kayra runs and manages the Kayra API server itself:
// serving it, running its reconciler, and clearing its caches. It
// always reads the server's own kayra.yaml directly — the
// end-user-facing counterpart that never touches local config or code
// is cmd/cli.
package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/infrapi/kayra/internal/apiserver"
	"github.com/infrapi/kayra/internal/catalog"
	gconfig "github.com/infrapi/kayra/internal/config"
	gcrypto "github.com/infrapi/kayra/internal/crypto"
	gstore "github.com/infrapi/kayra/internal/store"
	libconfig "github.com/infrapi/lib/pkg/config"
	liblistener "github.com/infrapi/lib/pkg/listener"
)

// configEnvVar names the environment variable that sets the --config
// flag's default, so a deployment can pin the config path without
// repeating --config on every invocation. An explicit --config always
// wins over it.
const configEnvVar = "KAYRA_CONFIG_FILE"

func main() {
	root := &cli.Command{
		Name:  "kayra",
		Usage: "authentication, namespace creation and IAM policy service",
		// A non-Local flag on the root is automatically available to
		// every subcommand (including nested ones, e.g. "cache clean"),
		// so --config never needs repeating on each command.
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Value:   "kayra.yaml",
				Sources: cli.EnvVars(configEnvVar),
				Usage:   "path to the Kayra YAML config",
			},
		},
		Commands: []*cli.Command{
			serveCommand(),
			reconcilerCommand(),
			cacheCommand(),
			tokenCommand(),
		},
		CommandNotFound: func(ctx context.Context, cmd *cli.Command, name string) {
			fmt.Fprintf(os.Stderr, "kayra: unknown command %q\n\n", name)
			_ = cli.ShowAppHelp(cmd)
			os.Exit(2)
		},
	}

	if err := root.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "kayra:", err)
		os.Exit(1)
	}
}

func serveCommand() *cli.Command {
	return &cli.Command{
		Name:  "serve",
		Usage: "run the Kayra API server",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			cfg, err := gconfig.Load(cmd.String("config"))
			if err != nil {
				return err
			}

			appVars := libconfig.NewConfigFromMap(cfg.App.ToVariables(), cmd.String("config"))
			appCfg, err := appVars.GetAppConfig()
			if err != nil {
				return fmt.Errorf("resolve app: config: %w", err)
			}

			engine, err := apiserver.Build(appCfg, cfg)
			if err != nil {
				return err
			}

			listener, err := liblistener.Listen(appCfg)
			if err != nil {
				return fmt.Errorf("listen: %w", err)
			}

			fmt.Printf("kayra: listening on %s\n", appCfg.AppListenAddress)
			return engine.RunListener(listener)
		},
	}
}

// reconcilerCommand runs catalog.Reconciler as its own long-lived process,
// deliberately separate from "serve": mixing it into the API server as a
// background goroutine would couple their lifecycles (a reconciler crash
// or a deploy of one forces the other) and bury its own log lines inside
// the request server's — running it as its own CLI invocation (its own
// process, container, or systemd unit) keeps the two independently
// debuggable, scalable and restartable.
func reconcilerCommand() *cli.Command {
	return &cli.Command{
		Name:   "reconciler",
		Usage:  "run the catalog namespace/subscription/stack reconciler",
		Action: runReconciler,
	}
}

func runReconciler(ctx context.Context, cmd *cli.Command) error {
	cfg, err := gconfig.Load(cmd.String("config"))
	if err != nil {
		return err
	}

	appVars := libconfig.NewConfigFromMap(cfg.App.ToVariables(), cmd.String("config"))
	appCfg, err := appVars.GetAppConfig()
	if err != nil {
		return fmt.Errorf("resolve app: config: %w", err)
	}

	_, dbBackend, err := cfg.ActiveDatabase()
	if err != nil {
		return err
	}
	s, keys, err := gstore.New(dbBackend)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer s.Close()

	repo := catalog.NewRepository(s, keys)
	r := catalog.NewReconciler(repo, appCfg.AppPlatform, appCfg.AppRegion, cfg.Reconciler)

	// SIGINT/SIGTERM cancels ctx so Reconciler.Run returns (ctx.Err()) on
	// its own instead of being killed mid-write — this is a long-running
	// foreground process meant to be stopped cleanly (by its container
	// runtime or systemd), not just abandoned.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("kayra: reconciler running for %s/%s (max_concurrent_reconciles=%d, default_mode=%q)\n",
		appCfg.AppPlatform, appCfg.AppRegion, cmp.Or(cfg.Reconciler.MaxConcurrentReconciles, catalog.DefaultMaxConcurrentReconciles), cfg.Reconciler.DefaultMode)
	if err := r.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("reconciler: %w", err)
	}
	fmt.Println("kayra: reconciler stopped")
	return nil
}

func cacheCommand() *cli.Command {
	return &cli.Command{
		Name:  "cache",
		Usage: "inspect and clear cached entries",
		Commands: []*cli.Command{
			{
				Name:  "clean",
				Usage: "clear cached JWKS and/or resolved-user entries directly in the configured store",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "scope", Value: "all", Usage: "what to clean: all, users, or auth"},
					&cli.StringFlag{Name: "authz", Usage: "users scope only: limit to one authorizations.<name> backend"},
					&cli.StringFlag{Name: "user", Usage: "users scope only: limit to one user id (requires --authz)"},
					&cli.StringFlag{Name: "provider", Usage: "auth scope only: limit to one authentifications.<name> provider"},
				},
				Action: runCacheClean,
			},
		},
	}
}

// runCacheClean clears cached entries directly in the configured store
// (etcd or local), so a config/code change (a new member_regex, a
// rotated JWKS key) takes effect on the next request instead of waiting
// out the TTL — see internal/authz/cache.go and internal/oidc/manager.go
// for what gets cached and why.
func runCacheClean(ctx context.Context, cmd *cli.Command) error {
	scope := cmd.String("scope")
	authzName := cmd.String("authz")
	user := cmd.String("user")
	provider := cmd.String("provider")

	if err := validateCacheFlags(scope, authzName, user, provider); err != nil {
		return err
	}

	cfg, err := gconfig.Load(cmd.String("config"))
	if err != nil {
		return err
	}

	_, dbBackend, err := cfg.ActiveDatabase()
	if err != nil {
		return err
	}
	s, keys, err := gstore.New(dbBackend)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer s.Close()

	var total int64
	switch scope {
	case "users":
		n, err := cleanUsers(s, keys, authzName, user)
		if err != nil {
			return err
		}
		total += n
	case "auth":
		n, err := cleanAuth(s, keys, provider)
		if err != nil {
			return err
		}
		total += n
	case "all":
		n, err := cleanUsers(s, keys, "", "")
		if err != nil {
			return err
		}
		total += n
		n, err = cleanAuth(s, keys, "")
		if err != nil {
			return err
		}
		total += n
	default:
		return fmt.Errorf("cache: unsupported --scope %q, want all, users or auth", scope)
	}

	fmt.Printf("kayra: deleted %d cache entr%s\n", total, plural(total))
	return nil
}

func validateCacheFlags(scope, authz, user, provider string) error {
	if user != "" && authz == "" {
		return fmt.Errorf("cache: --user requires --authz")
	}
	switch scope {
	case "all":
		if authz != "" || user != "" || provider != "" {
			return fmt.Errorf("cache: --authz/--user/--provider require --scope users or auth, not all")
		}
	case "users":
		if provider != "" {
			return fmt.Errorf("cache: --provider only applies to --scope auth")
		}
	case "auth":
		if authz != "" || user != "" {
			return fmt.Errorf("cache: --authz/--user only apply to --scope users")
		}
	default:
		return fmt.Errorf("cache: unsupported --scope %q, want all, users or auth", scope)
	}
	return nil
}

// cleanUsers deletes cached ResolveUser results: everything, one
// authorization backend's, or one user's, from narrowest to widest.
func cleanUsers(s gstore.Store, keys gstore.Keys, authz, user string) (int64, error) {
	switch {
	case user != "":
		return s.DeletePrefix(keys.UserCache(authz, user))
	case authz != "":
		return s.DeletePrefix(keys.UserCacheAuthzPrefix(authz))
	default:
		return s.DeletePrefix(keys.UserCachePrefix())
	}
}

// cleanAuth deletes cached JWKS: everything, or one provider's.
func cleanAuth(s gstore.Store, keys gstore.Keys, provider string) (int64, error) {
	if provider != "" {
		return s.DeletePrefix(keys.AuthCache(provider))
	}
	return s.DeletePrefix(keys.AuthCachePrefix())
}

func plural(n int64) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// tokenCommand mints tokens directly from the configured file/store,
// with no HTTP round trip and no prior session — the one way to get a
// first bearer token into a brand new deployment, before any real IdP
// group membership or RBAC object exists to authenticate the normal way.
func tokenCommand() *cli.Command {
	return &cli.Command{
		Name:  "token",
		Usage: "mint tokens directly from the configured config/store",
		Commands: []*cli.Command{
			{
				Name:  "mint",
				Usage: "mint a self-signed bootstrap JWT from an authentifications.<name>.local issuer key",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "provider", Required: true, Usage: "authentifications.<name> entry naming the local signing key to mint with"},
					&cli.StringFlag{Name: "subject", Value: "bootstrap", Usage: "the token's sub claim"},
					&cli.StringSliceFlag{Name: "group", Usage: "a group to embed in the token's groups claim; repeat for more than one"},
					&cli.DurationFlag{Name: "ttl", Value: time.Hour, Usage: "how long the token is valid for"},
				},
				Action: runTokenMint,
			},
		},
	}
}

func runTokenMint(ctx context.Context, cmd *cli.Command) error {
	cfg, err := gconfig.Load(cmd.String("config"))
	if err != nil {
		return err
	}

	name := cmd.String("provider")
	provider, ok := cfg.Authentifications[name]
	if !ok {
		return fmt.Errorf("token mint: authentifications.%s is not configured", name)
	}

	signingKeys, err := gcrypto.LoadSigningKeys(provider.Local)
	if err != nil {
		return fmt.Errorf("token mint: %w", err)
	}

	var issuer *gcrypto.SigningKey
	for i := range signingKeys {
		if signingKeys[i].Issuer {
			issuer = &signingKeys[i]
			break
		}
	}
	if issuer == nil {
		return fmt.Errorf("token mint: authentifications.%s has no local key with issuer: true", name)
	}

	token, err := gcrypto.MintSelfJWT(*issuer, cmd.String("subject"), cmd.StringSlice("group"), cmd.Duration("ttl"))
	if err != nil {
		return fmt.Errorf("token mint: %w", err)
	}
	fmt.Println(token)
	return nil
}
