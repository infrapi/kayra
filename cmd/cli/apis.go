package main

// `kayra-cli apis`, like `oc api-resources`: every api group the
// server knows (Kayra's own, plus every registered app) and the
// resources each one serves, from the server's GET /apis discovery —
// itself built from Kayra's live route table and from the OpenAPI spec
// the reconciler fetched for each registered app.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/urfave/cli/v3"
)

// discoveryGroup mirrors catalog.DiscoveryGroup (kept local so the CLI
// only depends on the wire format, not the server's packages).
type discoveryGroup struct {
	Api        string              `json:"api"`
	ShortName  string              `json:"short_name"`
	Owner      string              `json:"owner"`
	Builtin    bool                `json:"builtin"`
	SyncID     string              `json:"sync_id"`
	SpecSyncID string              `json:"spec_sync_id"`
	Resources  []discoveryResource `json:"resources"`
}

type discoveryResource struct {
	Name       string   `json:"name"`
	Namespaced bool     `json:"namespaced"`
	Verbs      []string `json:"verbs"`
}

func apisCommand() *cli.Command {
	return &cli.Command{
		Name:  "apis",
		Usage: "list every api group and the resources it serves (like `oc api-resources`)",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "api-group", Usage: "only this api group: its long name (\"telemetry.infrapi.io\"), its short name, or its first label (\"telemetry\")"},
			&cli.StringFlag{Name: "namespaced", Usage: "only namespaced (true) or cluster-scoped (false) resources"},
			&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Value: outputTable, Usage: "output format: table, json or yaml"},
			&cli.StringFlag{Name: "context", Usage: "saved context to use (defaults to the current context)"},
		},
		Action: runApis,
	}
}

func runApis(ctx context.Context, cmd *cli.Command) error {
	output := cmd.String("output")
	switch output {
	case outputTable, outputJSON, outputYAML:
	default:
		return fmt.Errorf("apis: --output must be %q, %q or %q, got %q", outputTable, outputJSON, outputYAML, output)
	}
	var namespaced *bool
	if v := cmd.String("namespaced"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("apis: --namespaced must be true or false, got %q", v)
		}
		namespaced = &b
	}

	c, err := resolveContext(cmd)
	if err != nil {
		return fmt.Errorf("apis: %w", err)
	}
	status, body, err := doVerbRequest(ctx, c, http.MethodGet, "/apis", nil)
	if err != nil {
		return fmt.Errorf("apis: %w", err)
	}
	if status != http.StatusOK {
		renderProblem(os.Stderr, status, body)
		os.Exit(1)
	}

	var groups []discoveryGroup
	if err := json.Unmarshal(body, &groups); err != nil {
		return fmt.Errorf("apis: decode GET /apis: %w", err)
	}
	groups = filterGroups(groups, cmd.String("api-group"), namespaced)

	switch output {
	case outputJSON, outputYAML:
		data, err := json.Marshal(groups)
		if err != nil {
			return err
		}
		if output == outputJSON {
			printJSON(os.Stdout, data)
		} else {
			printYAML(os.Stdout, data)
		}
		return nil
	}
	return renderApis(os.Stdout, os.Stderr, groups)
}

// filterGroups keeps the groups matching apiGroup (long name, short
// name or first label; "" keeps all) and, when namespaced is set, only
// their resources of that scope — dropping a group left with none.
func filterGroups(groups []discoveryGroup, apiGroup string, namespaced *bool) []discoveryGroup {
	out := []discoveryGroup{}
	for _, g := range groups {
		if apiGroup != "" && apiGroup != g.Api && apiGroup != g.ShortName && apiGroup != strings.SplitN(g.Api, ".", 2)[0] {
			continue
		}
		if namespaced != nil {
			var kept []discoveryResource
			for _, r := range g.Resources {
				if r.Namespaced == *namespaced {
					kept = append(kept, r)
				}
			}
			if len(kept) == 0 {
				continue
			}
			g.Resources = kept
		}
		out = append(out, g)
	}
	return out
}

// renderApis prints one row per resource. A registered api whose
// spec hasn't been fetched yet still gets a row (NAME "-"), so it's
// visible before its first sync.
func renderApis(stdout, stderr io.Writer, groups []discoveryGroup) error {
	if len(groups) == 0 {
		_, err := fmt.Fprintln(stderr, "No resources found.")
		return err
	}
	w := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tSHORTNAME\tAPIGROUP\tNAMESPACED\tVERBS")
	for _, g := range groups {
		short := g.ShortName
		if short == "" {
			short = "-"
		}
		if len(g.Resources) == 0 {
			_, _ = fmt.Fprintf(w, "-\t%s\t%s\t-\t-\n", short, g.Api)
			continue
		}
		for _, r := range g.Resources {
			verbs := strings.Join(r.Verbs, ",")
			if verbs == "" {
				verbs = "-"
			}
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%t\t%s\n", r.Name, short, g.Api, r.Namespaced, verbs)
		}
	}
	return w.Flush()
}
