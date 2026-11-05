// Command cli is the portable, end-user Kayra client: everything it
// does talks to a Kayra server's own API, never to local code or
// config — unlike cmd/kayra, which runs and manages the server
// itself (serve, reconciler, cache). This is the one binary meant to
// hand to someone who has nothing but a server URL: `kayra` (the
// server binary) always ships alongside kayra.yaml and the backends
// it configures; this one never does.
package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
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
			authCommand(),
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

// authCommand groups the two checks that ask a server about the
// current login itself rather than managing it: "can-i" (an
// authorization decision) and "whoami" (the identity that decision
// would be made against).
func authCommand() *cli.Command {
	return &cli.Command{
		Name:  "auth",
		Usage: "ask a server about the current login: can-i, whoami",
		Commands: []*cli.Command{
			canICommand(),
			whoamiCommand(),
		},
	}
}

// resolveContext picks --context by name, or the current context when
// --context is unset — the one piece every auth subcommand needs
// before it can call anything.
func resolveContext(cmd *cli.Command) (clicontext.Context, error) {
	f, err := clicontext.Load()
	if err != nil {
		return clicontext.Context{}, err
	}
	if name := cmd.String("context"); name != "" {
		c, ok := f.Contexts[name]
		if !ok {
			return clicontext.Context{}, fmt.Errorf("no such context %q", name)
		}
		return c, nil
	}
	_, c, err := f.Current()
	return c, err
}

// canICommand mirrors `kubectl auth can-i`: ask the server's own
// rbac.RegisterAuthorizeRoute check — POST /apis/authorization.<api
// -domain>/v1/check — whether the current context's own already
// -authenticated identity (never asserted locally) is granted verb on
// resource for --api. --api-domain is this one check endpoint's own
// mount point (a Kayra deployment's app.api_domain, "example.com" when
// a deployment never set one — see config.AppConfig.APIDomain); --api
// is the application being asked about (e.g. "compute.example.com"),
// an entirely different thing.
//
// This only ever tests rbac.Repository.Authorize — namespace-scoped
// Group/Role/RoleBinding objects, the mechanism other apps built on
// infrapi/lib use to authorize their own requests. It is never the
// mechanism Kayra's own management-plane routes use to gate
// themselves (see kayraOwnManagementWarning): asking about one of
// those still gets a real, truthful answer to "does a stored Rule
// grant this," just not necessarily the answer to "will the real
// endpoint let me."
func canICommand() *cli.Command {
	return &cli.Command{
		Name:        "can-i",
		Usage:       "check whether the current login can do <verb> on <resource>",
		Description: "Tests rbac.Authorize (namespace-scoped Group/Role/RoleBinding) — the authorization path other apps built on infrapi/lib use for their own API. Kayra's own management-plane routes (namespaces, stacks, cluster/namespace groups-roles-rolebindings, subscriptions) are gated by other mechanisms entirely and are never decided by this check — asking about one of those prints a warning alongside the answer.",
		ArgsUsage:   "<verb> <resource>",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "api", Required: true, Usage: "the API group being asked about, e.g. compute.example.com"},
			&cli.StringFlag{Name: "namespace", Required: true, Usage: "the namespace to check against"},
			&cli.StringFlag{Name: "api-domain", Usage: "the Kayra deployment's own app.api_domain, to reach its /apis/authorization.<domain>/v1/check — defaults to everything in --api past its first label, or \"example.com\" if --api has no dot"},
			&cli.StringFlag{Name: "context", Usage: "saved context to use (defaults to the current context)"},
		},
		Action: runCanI,
	}
}

func runCanI(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args()
	if args.Len() != 2 {
		return fmt.Errorf("can-i: usage: kayra-cli auth can-i <verb> <resource> --api <api> --namespace <namespace>")
	}
	verb, resource := args.Get(0), args.Get(1)

	c, err := resolveContext(cmd)
	if err != nil {
		return fmt.Errorf("can-i: %w", err)
	}

	api := cmd.String("api")
	apiDomain := resolveAPIDomain(cmd.String("api-domain"), api)

	if warning := kayraOwnManagementWarning(apiDomain, api, resource); warning != "" {
		fmt.Fprintln(os.Stderr, "kayra-cli: warning:", warning)
	}

	allowed, reason, err := checkAuthorized(ctx, c, apiDomain, cmd.String("namespace"), api, resource, verb)
	if err != nil {
		return fmt.Errorf("can-i: %w", err)
	}

	if allowed {
		fmt.Println("yes")
		return nil
	}
	fmt.Println("no")
	if reason != "" {
		fmt.Fprintln(os.Stderr, "kayra-cli:", reason)
	}
	os.Exit(1)
	return nil
}

// whoamiCommand prints exactly what the server's own
// GET /oauth2/userinfo returns for the current login: sub, provider,
// authorization, groups, and whatever authorizations.<name> attributes
// (email, name, ...) that backend resolved — the same identity any
// can-i decision or RBAC check against this token is actually made
// against, never asserted locally.
func whoamiCommand() *cli.Command {
	return &cli.Command{
		Name:  "whoami",
		Usage: "print the current login's identity and attributes, per the server's own userinfo",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "context", Usage: "saved context to use (defaults to the current context)"},
		},
		Action: runWhoami,
	}
}

func runWhoami(ctx context.Context, cmd *cli.Command) error {
	c, err := resolveContext(cmd)
	if err != nil {
		return fmt.Errorf("whoami: %w", err)
	}

	userinfoURL := strings.TrimRight(c.Server, "/") + "/oauth2/userinfo"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if err != nil {
		return fmt.Errorf("whoami: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("whoami: call %s: %w", userinfoURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("whoami: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("whoami: %s returned %d: %s", userinfoURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var attrs map[string]any
	if err := json.Unmarshal(body, &attrs); err != nil {
		return fmt.Errorf("whoami: parse response: %w", err)
	}

	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, name)
	}
	sort.Strings(names)

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	for _, name := range names {
		fmt.Fprintf(w, "%s:\t%s\n", name, formatUserinfoValue(attrs[name]))
	}
	return w.Flush()
}

// formatUserinfoValue renders one userinfo value for display: groups
// (and any other array-valued attribute) as a comma-separated list,
// everything else via its natural string form.
func formatUserinfoValue(v any) string {
	list, ok := v.([]any)
	if !ok {
		return fmt.Sprint(v)
	}
	parts := make([]string, len(list))
	for i, item := range list {
		parts[i] = fmt.Sprint(item)
	}
	return strings.Join(parts, ", ")
}

// resolveAPIDomain picks --api-domain when the caller set it, or else
// derives it from api itself: api is normally its own app's full URN
// ("compute.example.com"), and this deployment's own authorization.*
// check endpoint is mounted on that exact same domain — only the first
// label ("compute") differs. A bare api with no dot at all (unusual,
// but not invalid — see rbac.Rule.Apis) has no domain to derive, so
// this falls back to the server's own documented default.
func resolveAPIDomain(explicit, api string) string {
	if explicit != "" {
		return explicit
	}
	if i := strings.Index(api, "."); i >= 0 {
		return api[i+1:]
	}
	return "example.com"
}

// kayraOwnManagementWarning reports, when api/resource names one of
// Kayra's own management-plane resources (under apiDomain), which
// other mechanism actually gates it — none of them go through
// rbac.Authorize (what the /check endpoint, and so can-i, tests) at
// all:
//
//   - authorization.<domain>'s groups/roles/rolebindings and
//     subscription.<domain>'s subscriptions are gated by cluster RBAC
//     (rbac.CanManageNamespaceRBAC, via RequireClusterRBAC) — a
//     cluster-scoped Group/Role/RoleBinding check, a different data
//     set from the namespace-scoped one Authorize itself checks.
//   - authorization.<domain>'s clustergroups/clusterroles/
//     clusterrolebindings, catalog.<domain>'s stacks, and
//     apps.<domain>'s namespaces are gated by middleware.SysadminGate
//     alone — whether the caller's groups intersect sysadmin.groups,
//     no Rule of any kind consulted.
//
// Empty when api/resource doesn't name one of these — including any
// api that simply isn't under apiDomain at all, since that's another
// app's own API, exactly what Authorize is for.
// singularizeResource strips a trailing "s" so "group"/"groups",
// "role"/"roles", etc. both match — a human typing `can-i ... delete
// group` means exactly the same resource as the real route's own
// "groups", and kayraOwnManagementWarning would otherwise miss it on
// a plain string mismatch.
func singularizeResource(resource string) string {
	return strings.TrimSuffix(resource, "s")
}

func kayraOwnManagementWarning(apiDomain, api, resource string) string {
	switch api {
	case "authorization." + apiDomain:
		switch singularizeResource(resource) {
		case "group", "role", "rolebinding":
			return "namespace groups/roles/rolebindings are gated by cluster RBAC (CanManageNamespaceRBAC), never by this check — it tests a different, namespace-scoped Group/Role/RoleBinding set"
		case "clustergroup", "clusterrole", "clusterrolebinding":
			return "cluster groups/roles/rolebindings are gated by the sysadmin group alone (SysadminGate) — compare `auth whoami`'s groups against sysadmin.groups yourself, this check can't see either"
		}
	case "subscription." + apiDomain:
		return "subscriptions are gated by cluster RBAC (CanManageNamespaceRBAC), never by this check — it tests a different, namespace-scoped Group/Role/RoleBinding set"
	case "catalog." + apiDomain:
		return "stacks are gated by the sysadmin group alone (SysadminGate) — compare `auth whoami`'s groups against sysadmin.groups yourself, this check can't see either"
	case "apps." + apiDomain:
		return "namespaces are gated by the sysadmin group alone (SysadminGate) — compare `auth whoami`'s groups against sysadmin.groups yourself, this check can't see either"
	}
	return ""
}

// checkAuthorized POSTs c's own bearer token against server's
// /apis/authorization.<apiDomain>/v1/check — the exact same
// rbac.AuthorizeRequest/AuthorizeResponse shape infrapi/lib's own auth
// client uses, so this never duplicates or re-derives the decision
// itself, only asks for it.
func checkAuthorized(ctx context.Context, c clicontext.Context, apiDomain, namespace, api, resource, verb string) (allowed bool, reason string, err error) {
	body, err := json.Marshal(map[string]string{
		"namespace": namespace,
		"api":       api,
		"resource":  resource,
		"verb":      verb,
	})
	if err != nil {
		return false, "", fmt.Errorf("encode request: %w", err)
	}

	checkURL := strings.TrimRight(c.Server, "/") + "/apis/authorization." + apiDomain + "/v1/check"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, checkURL, bytes.NewReader(body))
	if err != nil {
		return false, "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("call %s: %w", checkURL, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var problem struct {
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(respBody, &problem)
		if problem.Detail != "" {
			return false, "", fmt.Errorf("%s returned %d: %s", checkURL, resp.StatusCode, problem.Detail)
		}
		return false, "", fmt.Errorf("%s returned %d", checkURL, resp.StatusCode)
	}

	var result struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return false, "", fmt.Errorf("parse response: %w", err)
	}
	return result.Allowed, result.Reason, nil
}
