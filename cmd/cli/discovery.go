package main

// What kayra-cli learns from the server instead of being configured:
// Kayra's own endpoints and API domain, from /.well-known/kayra.json, and
// every api group's full name, from GET /apis — the way kubectl resolves
// a resource through discovery rather than a local setting.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/infrapi/kayra/internal/clicontext"
)

// kayraDocumentPath mirrors discovery.Path (kept local so the CLI only
// depends on the wire format, not the server's packages).
const kayraDocumentPath = "/.well-known/kayra.json"

// kayraDocument mirrors discovery.Document.
type kayraDocument struct {
	Domain    string            `json:"domain"`
	APIs      map[string]string `json:"apis"`
	Endpoints struct {
		Userinfo string `json:"userinfo"`
		Check    string `json:"check"`
		JWKS     string `json:"jwks"`
		APIs     string `json:"apis"`
	} `json:"endpoints"`
}

// fetchKayra reads c's server's discovery document. It needs no token.
func fetchKayra(ctx context.Context, c clicontext.Context) (kayraDocument, error) {
	var doc kayraDocument
	docURL := strings.TrimRight(c.Server, "/") + kayraDocumentPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return doc, fmt.Errorf("build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("call %s: %w", docURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return doc, fmt.Errorf("read %s: %w", docURL, err)
	}
	if resp.StatusCode != http.StatusOK {
		return doc, fmt.Errorf("%s returned %d: is %s a Kayra server?", docURL, resp.StatusCode, c.Server)
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return doc, fmt.Errorf("decode %s: %w", docURL, err)
	}
	if doc.Endpoints.Check == "" {
		return doc, fmt.Errorf("%s names no check endpoint", docURL)
	}
	return doc, nil
}

// builtinGroup is the full name of Kayra's built-in group name (system,
// catalog, authorization) per doc, "" when doc has no such group.
func (doc kayraDocument) builtinGroup(name string) string {
	path, ok := doc.APIs[name]
	if !ok {
		return ""
	}
	// /apis/<group>/v1
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// resolveAPI turns what a user typed for an api into its full group name.
// A name with a dot already is one ("compute.infrapi.io",
// "vault.infrapi.io"). Otherwise it is looked up in the server's
// GET /apis: a group's short name, or the first label of its name
// ("catalog", "compute"), which must name exactly one group.
func resolveAPI(ctx context.Context, c clicontext.Context, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("an api is required")
	}
	if strings.Contains(name, ".") {
		return name, nil
	}
	status, body, err := doVerbRequest(ctx, c, http.MethodGet, "/apis", nil)
	if err != nil {
		return "", fmt.Errorf("resolve api %q: %w", name, err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("resolve api %q: GET /apis returned %d", name, status)
	}
	var groups []discoveryGroup
	if err := json.Unmarshal(body, &groups); err != nil {
		return "", fmt.Errorf("resolve api %q: decode GET /apis: %w", name, err)
	}
	return matchAPI(groups, name)
}

// matchAPI is resolveAPI's lookup of a name without a dot in groups.
func matchAPI(groups []discoveryGroup, name string) (string, error) {
	var matches []string
	for _, g := range groups {
		if g.ShortName == name {
			return g.Api, nil
		}
		if strings.SplitN(g.Api, ".", 2)[0] == name {
			matches = append(matches, g.Api)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", fmt.Errorf("no api group named %q: list them with `kayra-cli apis`, or give the full name", name)
	default:
		return "", fmt.Errorf("%q names several api groups (%s): give the full name", name, strings.Join(matches, ", "))
	}
}
