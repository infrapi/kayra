package main

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRenderTableList(t *testing.T) {
	created := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	updated := time.Date(2026, 11, 10, 14, 30, 0, 0, time.UTC)
	body := []byte(`[
		{"api":"telemetry.giservices.io","active":true,"state":"success","created_at":"2026-11-01T09:00:00Z","updated_at":"2026-11-10T14:30:00Z"},
		{"api":"compute.example.com","active":false,"state":"init"}
	]`)
	var out, errOut bytes.Buffer
	ok, err := renderTable(&out, &errOut, body, "core")
	if err != nil || !ok {
		t.Fatalf("renderTable: ok=%v err=%v", ok, err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want header + 2 rows:\n%s", len(lines), out.String())
	}
	if got := strings.Fields(lines[0]); strings.Join(got, " ") != "NAMESPACE NAME CREATED AT UPDATED AT" {
		t.Fatalf("header = %q", lines[0])
	}
	want1 := []string{"core", "telemetry.giservices.io", created.Local().Format(time.RFC3339), updated.Local().Format(time.RFC3339)}
	if got := strings.Fields(lines[1]); strings.Join(got, " ") != strings.Join(want1, " ") {
		t.Fatalf("row 1 = %q, want fields %q", lines[1], want1)
	}
	// No timestamps (a record from before they existed): "-".
	if got := strings.Fields(lines[2]); strings.Join(got, " ") != "core compute.example.com - -" {
		t.Fatalf("row 2 = %q", lines[2])
	}
	// Only those four columns: nothing else from the body leaks in.
	if strings.Contains(out.String(), "success") || strings.Contains(out.String(), "STATE") {
		t.Fatalf("table shows more than namespace/name/timestamps:\n%s", out.String())
	}
}

func TestRenderTableClusterScopedSingleObject(t *testing.T) {
	var out, errOut bytes.Buffer
	ok, err := renderTable(&out, &errOut, []byte(`{"name":"vault.example.com","owner":"sre"}`), "")
	if err != nil || !ok {
		t.Fatalf("renderTable: ok=%v err=%v", ok, err)
	}
	if strings.Contains(out.String(), "NAMESPACE") {
		t.Fatalf("cluster-scoped resource shows a NAMESPACE column:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "vault.example.com") {
		t.Fatalf("missing the name:\n%s", out.String())
	}
}

func TestRenderTableEmptyAndUnnamed(t *testing.T) {
	var out, errOut bytes.Buffer
	if ok, _ := renderTable(&out, &errOut, []byte(`[]`), "core"); !ok || out.Len() != 0 || !strings.Contains(errOut.String(), "No resources found.") {
		t.Fatalf("empty list: ok=%v stdout=%q stderr=%q", ok, out.String(), errOut.String())
	}
	// Not a named resource (e.g. a status document): the caller falls back to JSON.
	if ok, _ := renderTable(&out, &errOut, []byte(`{"allowed":true}`), ""); ok {
		t.Fatalf("unnamed object: want ok=false so the caller prints JSON")
	}
}

func TestPrintVerbResponseDeleteAndFallback(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := printVerbResponse(&out, &errOut, outputTable, "delete", "subscriptions", "vault.example.com", "core", nil); err != nil {
		t.Fatal(err)
	}
	if out.String() != "subscriptions \"vault.example.com\" deleted\n" {
		t.Fatalf("delete = %q", out.String())
	}

	out.Reset()
	if err := printVerbResponse(&out, &errOut, outputTable, "get", "apiregistrations", "vault.example.com/status", "", []byte(`{"sync_id":"v2","subscriptions":[]}`)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"sync_id": "v2"`) {
		t.Fatalf("unnamed body should fall back to pretty JSON, got %q", out.String())
	}

	out.Reset()
	if err := printVerbResponse(&out, &errOut, outputJSON, "get", "subscriptions", "", "core", []byte(`[{"api":"a","state":"init"}]`)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"state": "init"`) {
		t.Fatalf("-o json should print the full body, got %q", out.String())
	}
}

func TestRenderProblem(t *testing.T) {
	var errOut bytes.Buffer
	renderProblem(&errOut, http.StatusForbidden, []byte(`{"status":403,"title":"Forbidden","detail":"namespace \"core\" is not subscribed to api \"telemetry.giservices.io\"","solution":"subscribe first"}`))
	want := "Error: Forbidden (403): namespace \"core\" is not subscribed to api \"telemetry.giservices.io\"\nSolution: subscribe first\n"
	if errOut.String() != want {
		t.Fatalf("renderProblem = %q, want %q", errOut.String(), want)
	}

	errOut.Reset()
	renderProblem(&errOut, http.StatusBadGateway, []byte("upstream down"))
	if errOut.String() != "Error: Bad Gateway (502): upstream down\n" {
		t.Fatalf("non-problem body = %q", errOut.String())
	}
}

func TestPrintYAML(t *testing.T) {
	var out bytes.Buffer
	printYAML(&out, []byte(`[{"api":"telemetry.giservices.io","active":true,"state":"init","current_sync_id":"","count":3,"version":"1.0","flag":"true","depends_on":[{"name":"a"}],"metadata":{"namespace":"core"},"none":null}]`))
	want := `- api: telemetry.giservices.io
  active: true
  state: init
  current_sync_id: ""
  count: 3
  version: "1.0"
  flag: "true"
  depends_on:
    - name: a
  metadata:
    namespace: core
  none: null
`
	if out.String() != want {
		t.Fatalf("printYAML =\n%s\nwant\n%s", out.String(), want)
	}

	out.Reset()
	printYAML(&out, []byte("not json"))
	if out.String() != "not json\n" {
		t.Fatalf("non-JSON body = %q, want it verbatim", out.String())
	}
}

func TestApisFilterAndRender(t *testing.T) {
	groups := []discoveryGroup{
		{Api: "catalog.example.com", Builtin: true, Resources: []discoveryResource{
			{Name: "apiregistrations", Verbs: []string{"get", "list"}},
			{Name: "subscriptions", Namespaced: true, Verbs: []string{"create", "list"}},
		}},
		{Api: "telemetry.giservices.io", ShortName: "telemetry", Resources: []discoveryResource{
			{Name: "dashboards", Namespaced: true, Verbs: []string{"list"}},
		}},
		{Api: "vault.example.com", Resources: []discoveryResource{}}, // spec not fetched yet
	}

	var out, errOut bytes.Buffer
	if err := renderApis(&out, &errOut, groups); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	want := [][]string{
		{"NAME", "SHORTNAME", "APIGROUP", "NAMESPACED", "VERBS"},
		{"apiregistrations", "-", "catalog.example.com", "false", "get,list"},
		{"subscriptions", "-", "catalog.example.com", "true", "create,list"},
		{"dashboards", "telemetry", "telemetry.giservices.io", "true", "list"},
		{"-", "-", "vault.example.com", "-", "-"},
	}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d:\n%s", len(lines), len(want), out.String())
	}
	for i, w := range want {
		if got := strings.Fields(lines[i]); strings.Join(got, " ") != strings.Join(w, " ") {
			t.Errorf("line %d = %q, want %q", i, lines[i], w)
		}
	}

	yes := true
	if got := filterGroups(groups, "", &yes); len(got) != 2 || got[0].Resources[0].Name != "subscriptions" {
		t.Fatalf("--namespaced=true = %+v", got)
	}
	for _, sel := range []string{"telemetry.giservices.io", "telemetry"} {
		if got := filterGroups(groups, sel, nil); len(got) != 1 || got[0].Api != "telemetry.giservices.io" {
			t.Fatalf("--api-group %s = %+v", sel, got)
		}
	}
	if got := filterGroups(groups, "catalog", nil); len(got) != 1 || got[0].Api != "catalog.example.com" {
		t.Fatalf("--api-group catalog (first label) = %+v", got)
	}

	out.Reset()
	errOut.Reset()
	if err := renderApis(&out, &errOut, nil); err != nil || out.Len() != 0 || !strings.Contains(errOut.String(), "No resources found.") {
		t.Fatalf("empty: stdout %q stderr %q", out.String(), errOut.String())
	}
}
