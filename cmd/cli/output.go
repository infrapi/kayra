package main

// Human-readable rendering of the generic verbs' responses (see
// verbs.go): a table of NAMESPACE (namespaced resources only), NAME,
// CREATED AT and UPDATED AT — the same style as `context list`. Use
// -o json or -o yaml for every field.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/tabwriter"
	"time"

	"gopkg.in/yaml.v3"
)

// Output formats accepted by --output.
const (
	outputTable = "table"
	outputJSON  = "json"
	outputYAML  = "yaml"
)

// nameKeys are the fields a resource's name is read from, first match
// wins: "name" for almost everything, "api" for a subscription (which is
// named by the api it subscribes to).
var nameKeys = []string{"name", "api"}

// renderTable writes body as a table to stdout. namespace is the -n
// value: non-empty adds the NAMESPACE column. ok is false when body
// isn't a resource or a list of resources (no name to show), so the
// caller can fall back to JSON. An empty list prints nothing on stdout
// and a kubectl-style notice on stderr, so a script reading stdout sees
// no rows rather than a sentence.
func renderTable(stdout, stderr io.Writer, body []byte, namespace string) (ok bool, err error) {
	rows, ok := resourceRows(body)
	if !ok {
		return false, nil
	}
	if len(rows) == 0 {
		_, err := fmt.Fprintln(stderr, "No resources found.")
		return true, err
	}

	w := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	if namespace != "" {
		_, _ = fmt.Fprint(w, "NAMESPACE\t")
	}
	_, _ = fmt.Fprintln(w, "NAME\tCREATED AT\tUPDATED AT")
	for _, row := range rows {
		if namespace != "" {
			_, _ = fmt.Fprintf(w, "%s\t", namespace)
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", rowName(row), timestampCell(row["created_at"]), timestampCell(row["updated_at"]))
	}
	return true, w.Flush()
}

// resourceRows decodes body as a list of resources, or a single one as
// a one-row list. ok is false unless every row has a name.
func resourceRows(body []byte) (rows []map[string]any, ok bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, false
	}
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &rows); err != nil {
			return nil, false
		}
	} else {
		var one map[string]any
		if err := json.Unmarshal(trimmed, &one); err != nil {
			return nil, false
		}
		rows = []map[string]any{one}
	}
	for _, row := range rows {
		if rowName(row) == "" {
			return nil, false
		}
	}
	return rows, true
}

func rowName(row map[string]any) string {
	for _, k := range nameKeys {
		if s, ok := row[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// timestampCell renders an RFC 3339 timestamp in local time, like
// `context list`'s EXPIRY; "-" when absent (a record written before
// timestamps existed, or a resource that has none).
func timestampCell(v any) string {
	s, _ := v.(string)
	if s == "" {
		return "-"
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return s
	}
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format(time.RFC3339)
}

// renderProblem writes an error response readably to stderr: an
// infrapi/lib problem detail (every Kayra error, see internal/httpapi)
// as "Error: <title> (<status>): <detail>" plus its solution, anything
// else as the status and raw body.
func renderProblem(stderr io.Writer, status int, body []byte) {
	var p struct {
		Title    string `json:"title"`
		Detail   string `json:"detail"`
		Solution string `json:"solution"`
	}
	title := http.StatusText(status)
	if title == "" {
		title = "HTTP error"
	}
	if err := json.Unmarshal(body, &p); err == nil && p.Detail != "" {
		if p.Title != "" {
			title = p.Title
		}
		_, _ = fmt.Fprintf(stderr, "Error: %s (%d): %s\n", title, status, p.Detail)
		if p.Solution != "" {
			_, _ = fmt.Fprintf(stderr, "Solution: %s\n", p.Solution)
		}
		return
	}
	msg := fmt.Sprintf("Error: %s (%d)", title, status)
	if b := strings.TrimSpace(string(body)); b != "" {
		msg += ": " + b
	}
	_, _ = fmt.Fprintln(stderr, msg)
}

// printJSON pretty-prints body as JSON when it parses as such, falling
// back to the raw bytes verbatim otherwise.
func printJSON(w io.Writer, body []byte) {
	if len(body) == 0 {
		return
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "", "  "); err == nil {
		_, _ = fmt.Fprintln(w, pretty.String())
		return
	}
	_, _ = fmt.Fprintln(w, string(body))
}

// printYAML prints a JSON body as YAML, keeping the server's key order
// (JSON is valid YAML, so it parses straight into a yaml.Node; only its
// flow/quote styles are reset so it encodes as ordinary block YAML).
// A body that isn't JSON is printed verbatim.
func printYAML(w io.Writer, body []byte) {
	if len(bytes.TrimSpace(body)) == 0 {
		return
	}
	var doc yaml.Node
	if !json.Valid(body) || yaml.Unmarshal(body, &doc) != nil {
		_, _ = fmt.Fprintln(w, string(body))
		return
	}
	clearStyle(&doc)
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		_, _ = fmt.Fprintln(w, string(body))
		return
	}
	_ = enc.Close()
	_, _ = w.Write(out.Bytes())
}

func clearStyle(n *yaml.Node) {
	n.Style = 0
	for _, c := range n.Content {
		clearStyle(c)
	}
}
