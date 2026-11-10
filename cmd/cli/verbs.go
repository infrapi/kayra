// Top-level kubectl-style verbs — get, create, update, patch, delete
// — each a thin, generic REST client against any app's own namespaced
// API, following the exact URN/route convention Kayra's own
// namespace-scoped resources use (see RegisterNamespaceRoutes). `get`
// with no trailing <name> lists the whole collection, exactly like
// `kubectl get` does — there is no separate `list` verb.
//
//	{server}/apis/<api>.<domain>/v1/namespaces/<namespace>/<resource>[/<name>]
//
// authenticated with the current context's own bearer token. Kayra
// itself never implements any of these APIs (see catalog.ApiRegistration
// — Kayra only tracks that one exists and who owns it); this is just
// the one HTTP convention every app following it shares, so one verb
// set works against all of them without kayra-cli knowing anything
// about any particular one. <api> may be given bare ("compute") or
// already domain-qualified ("compute.example.com") — see
// resolveAPIDomain, shared with `auth can-i`.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/infrapi/kayra/internal/clicontext"
)

// nameMode says whether a verb's trailing <name> (one item, not the
// whole collection) may, must, or can't appear.
type nameMode int

const (
	nameNone     nameMode = iota // create: always the collection, never one item
	nameOptional                 // get: list the collection when absent, that one item when given — kubectl's own `get` does the same
	nameRequired                 // update/patch/delete: always exactly one item
)

// verbSpec says what a verb needs beyond <api>/<resource>: whether a
// trailing <name> is allowed/required, and whether it takes a request
// body.
type verbSpec struct {
	name        nameMode
	requireBody bool
}

// verbCommands returns every supported verb, each wired to the same
// runVerb with its own HTTP method and verbSpec. All are plain GET
// except where noted — `get` mirrors Kayra's own collection vs. item
// routes (e.g. GET .../subscriptions vs. GET .../subscriptions/:api)
// by the same means `kubectl get` does: list the collection when no
// <name> is given, fetch that one item when it is.
func verbCommands() []*cli.Command {
	return []*cli.Command{
		verbCommand("get", http.MethodGet, verbSpec{name: nameOptional}),
		verbCommand("create", http.MethodPost, verbSpec{name: nameNone, requireBody: true}),
		verbCommand("update", http.MethodPut, verbSpec{name: nameRequired, requireBody: true}),
		verbCommand("patch", http.MethodPatch, verbSpec{name: nameRequired, requireBody: true}),
		verbCommand("delete", http.MethodDelete, verbSpec{name: nameRequired}),
	}
}

func verbCommand(verb, method string, spec verbSpec) *cli.Command {
	argsUsage := "<api> <resource>"
	switch spec.name {
	case nameOptional:
		argsUsage = "<api> <resource> [<name>]"
	case nameRequired:
		argsUsage = "<api> <resource> <name>"
	}
	usage := fmt.Sprintf("%s a resource under any app's own API (kubectl-style)", verb)
	flags := []cli.Flag{
		&cli.StringFlag{Name: "namespace", Aliases: []string{"n"}, Usage: "the namespace to address — omit for a cluster-scoped resource (e.g. catalog's apiregistrations, authorization's clustergroups/clusterroles/clusterrolebindings)"},
		&cli.StringFlag{Name: "api-domain", Usage: "this api's own domain — defaults to everything in <api> past its first label, or \"example.com\" if <api> has no dot"},
		&cli.StringFlag{Name: "context", Usage: "saved context to use (defaults to the current context)"},
		&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Value: outputTable, Usage: "output format: table (namespace, name, created/updated at), or json / yaml (the full response)"},
	}
	if spec.requireBody {
		flags = append(flags,
			&cli.StringFlag{Name: "data", Aliases: []string{"d"}, Usage: "request body, as a raw JSON string"},
			&cli.StringFlag{Name: "filename", Aliases: []string{"f"}, Usage: "request body, read from a file (\"-\" for stdin)"},
		)
	}

	return &cli.Command{
		Name:      verb,
		Usage:     usage,
		ArgsUsage: argsUsage,
		Flags:     flags,
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runVerb(ctx, cmd, verb, method, spec)
		},
	}
}

func runVerb(ctx context.Context, cmd *cli.Command, verb, method string, spec verbSpec) error {
	args := cmd.Args()
	minArgs, maxArgs := 2, 2
	if spec.name == nameOptional {
		maxArgs = 3
	}
	if spec.name == nameRequired {
		minArgs, maxArgs = 3, 3
	}
	if args.Len() < minArgs || args.Len() > maxArgs {
		nameUsage := ""
		switch spec.name {
		case nameOptional:
			nameUsage = " [<name>]"
		case nameRequired:
			nameUsage = " <name>"
		}
		return fmt.Errorf("%s: usage: kayra-cli %s <api> <resource>%s [-n <namespace>]", verb, verb, nameUsage)
	}
	apiName, resource := args.Get(0), args.Get(1)
	var name string
	if args.Len() == 3 {
		name = args.Get(2)
	}

	output := cmd.String("output")
	switch output {
	case outputTable, outputJSON, outputYAML:
	default:
		return fmt.Errorf("%s: --output must be %q, %q or %q, got %q", verb, outputTable, outputJSON, outputYAML, output)
	}

	c, err := resolveContext(cmd)
	if err != nil {
		return fmt.Errorf("%s: %w", verb, err)
	}

	var body []byte
	if spec.requireBody {
		body, err = readVerbBody(cmd)
		if err != nil {
			return fmt.Errorf("%s: %w", verb, err)
		}
		if len(body) == 0 {
			return fmt.Errorf("%s: a request body is required (--data or --filename)", verb)
		}
	}

	apiDomain := resolveAPIDomain(cmd.String("api-domain"), apiName, c.ApiDomain)
	fullAPI := apiName
	if !strings.Contains(apiName, ".") {
		fullAPI = apiName + "." + apiDomain
	}

	// A namespace scopes the resource under .../namespaces/<ns>/<resource>
	// (subscriptions, per-namespace groups/roles/rolebindings, ...);
	// omitted, <resource> is cluster-scoped and addressed directly —
	// .../<resource> (apiregistrations, clustergroups/clusterroles/
	// clusterrolebindings, ...). Kayra itself mounts both shapes under
	// the same api group, never both for the same resource name, so
	// there is nothing to disambiguate beyond what the caller already
	// knows about the resource they're naming.
	namespace := cmd.String("namespace")
	var path string
	if namespace != "" {
		path = fmt.Sprintf("/apis/%s/v1/namespaces/%s/%s", fullAPI, namespace, resource)
	} else {
		path = fmt.Sprintf("/apis/%s/v1/%s", fullAPI, resource)
	}
	if name != "" {
		path += "/" + name
	}

	status, respBody, err := doVerbRequest(ctx, c, method, path, body)
	if err != nil {
		return fmt.Errorf("%s: %w", verb, err)
	}

	if status < 200 || status >= 300 {
		switch output {
		case outputJSON:
			printJSON(os.Stdout, respBody)
		case outputYAML:
			printYAML(os.Stdout, respBody)
		default:
			renderProblem(os.Stderr, status, respBody)
		}
		os.Exit(1)
	}
	return printVerbResponse(os.Stdout, os.Stderr, output, verb, resource, name, namespace, respBody)
}

// printVerbResponse prints a successful response: the full body for -o
// json / yaml; otherwise the table (see renderTable), a one-line confirmation
// for a delete's empty body, and the pretty JSON for anything that
// isn't a named resource (so nothing is ever hidden).
func printVerbResponse(stdout, stderr io.Writer, output, verb, resource, name, namespace string, body []byte) error {
	switch output {
	case outputJSON:
		printJSON(stdout, body)
		return nil
	case outputYAML:
		printYAML(stdout, body)
		return nil
	}
	if len(bytes.TrimSpace(body)) == 0 {
		if verb == "delete" {
			_, err := fmt.Fprintf(stdout, "%s %q deleted\n", resource, name)
			return err
		}
		return nil
	}
	ok, err := renderTable(stdout, stderr, body, namespace)
	if err != nil || ok {
		return err
	}
	printJSON(stdout, body)
	return nil
}

// readVerbBody resolves a verb's request body: --data verbatim,
// --filename read from disk ("-" for stdin), or neither — in which
// case runVerb reports the missing body itself. The two flags are
// mutually exclusive in practice (a caller naming both gets --data
// silently preferred) rather than cross-validated: this is a thin
// client with no reason to duplicate validation the server already
// does on the body itself.
func readVerbBody(cmd *cli.Command) ([]byte, error) {
	if data := cmd.String("data"); data != "" {
		return []byte(data), nil
	}
	if filename := cmd.String("filename"); filename != "" {
		if filename == "-" {
			return io.ReadAll(os.Stdin)
		}
		return os.ReadFile(filename) //#nosec G304 -- filename is this user's own --filename flag, never attacker input
	}
	return nil, nil
}

// doVerbRequest sends one request against c's own server, bearer
// -authenticated exactly like checkAuthorized's call to /check — the
// same context, the same trust, just a caller-named path instead of a
// fixed one.
func doVerbRequest(ctx context.Context, c clicontext.Context, method, path string, body []byte) (int, []byte, error) {
	reqURL := strings.TrimRight(c.Server, "/") + path

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, reqURL, reader)
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("call %s: %w", reqURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("read response: %w", err)
	}
	return resp.StatusCode, respBody, nil
}
