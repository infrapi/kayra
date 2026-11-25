package api

import (
	"context"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// Every contract is valid OpenAPI: server.WithOpenAPI refuses to start
// on one that is not.
func TestContracts(t *testing.T) {
	for _, c := range Contracts() {
		doc, err := openapi3.NewLoader().LoadFromData(c.Content)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if err := doc.Validate(context.Background()); err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
	}
}

// SetDomain moves Kayra's groups, their roots and the contracts served to
// the domain; an example's group stays.
func TestSetDomain(t *testing.T) {
	defer SetDomain(contractDomain)
	SetDomain("example.com")
	SetDomain("example.com") // once more: the same
	if RbacGroup != "authorization.example.com" || RbacRoots[0] != "/apis/authorization.example.com/v1" {
		t.Errorf("rbac: %s %v", RbacGroup, RbacRoots)
	}
	for _, s := range Served() {
		if s.Root == "" || !strings.Contains(s.Root, ".example.com/") {
			t.Errorf("%s: root %s", s.Name, s.Root)
		}
		content := string(s.Content)
		if strings.Contains(content, "/apis/system.infrapi.io/") || strings.Contains(content, "x-infrapi-group: catalog.infrapi.io") {
			t.Errorf("%s: still infrapi.io", s.Name)
		}
		if s.Name == "rbac v1" && !strings.Contains(content, "compute.infrapi.io") {
			t.Errorf("%s: its examples moved", s.Name)
		}
		doc, err := openapi3.NewLoader().LoadFromData(s.Content)
		if err != nil {
			t.Fatal(err)
		}
		for p := range doc.Paths.Map() {
			if !strings.HasPrefix(p, s.Root) {
				t.Errorf("%s: path %s not under %s", s.Name, p, s.Root)
			}
		}
	}
}
