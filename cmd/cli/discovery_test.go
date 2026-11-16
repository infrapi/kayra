package main

import (
	"strings"
	"testing"
)

func TestMatchAPI(t *testing.T) {
	groups := []discoveryGroup{
		{Api: "system.infrapi.io", Builtin: true},
		{Api: "catalog.infrapi.io", Builtin: true},
		{Api: "compute.infrapi.io", ShortName: "vm"},
		{Api: "vault.infrapi.io", ShortName: "vault"},
		{Api: "vault.ops.infrapi.io"},
	}
	for name, want := range map[string]string{
		"catalog": "catalog.infrapi.io", // first label
		"compute": "compute.infrapi.io", // first label
		"vm":      "compute.infrapi.io", // short name
		"vault":   "vault.infrapi.io",   // a short name wins over first labels
	} {
		got, err := matchAPI(groups, name)
		if err != nil || got != want {
			t.Errorf("matchAPI(%q) = %q, %v; want %q", name, got, err, want)
		}
	}
	if _, err := matchAPI(groups, "nope"); err == nil || !strings.Contains(err.Error(), "kayra-cli apis") {
		t.Errorf("unknown api: %v", err)
	}
	ambiguous := append(groups, discoveryGroup{Api: "compute.ops.infrapi.io"})
	if _, err := matchAPI(ambiguous, "compute"); err == nil || !strings.Contains(err.Error(), "several") {
		t.Errorf("ambiguous api: %v", err)
	}
}

func TestBuiltinGroupAndWarning(t *testing.T) {
	doc := kayraDocument{Domain: "infrapi.io", APIs: map[string]string{
		"system":        "/apis/system.infrapi.io/v1",
		"catalog":       "/apis/catalog.infrapi.io/v1",
		"authorization": "/apis/authorization.infrapi.io/v1",
	}}
	if got := doc.builtinGroup("catalog"); got != "catalog.infrapi.io" {
		t.Errorf("builtinGroup(catalog) = %q", got)
	}
	if got := doc.builtinGroup("nope"); got != "" {
		t.Errorf("builtinGroup(nope) = %q", got)
	}
	if w := kayraOwnManagementWarning(doc, "catalog.infrapi.io", "subscriptions"); !strings.Contains(w, "cluster RBAC") {
		t.Errorf("subscriptions warning: %q", w)
	}
	if w := kayraOwnManagementWarning(doc, "system.infrapi.io", "namespaces"); !strings.Contains(w, "sysadmin") {
		t.Errorf("namespaces warning: %q", w)
	}
	// another app's API, even on Kayra's domain: what the check is for
	if w := kayraOwnManagementWarning(doc, "compute.infrapi.io", "vms"); w != "" {
		t.Errorf("compute warning: %q", w)
	}
	// an empty document never matches an empty api
	if w := kayraOwnManagementWarning(kayraDocument{}, "", "groups"); w != "" {
		t.Errorf("empty warning: %q", w)
	}
}
