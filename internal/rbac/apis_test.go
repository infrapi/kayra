package rbac

import "testing"

func TestImplicitAPI(t *testing.T) {
	const me = "system:api:compute.infrapi.io"
	for _, c := range []struct {
		caller, api, resource, verb, name string
		want                              bool
	}{
		{me, "catalog.infrapi.io", "apiregistrations", "get", "compute.infrapi.io", true},
		{me, "catalog.infrapi.io", "apiregistrations/status", "list", "compute.infrapi.io", true},
		{me, "catalog.infrapi.io", "apiregistrations", "update", "compute.infrapi.io", false},
		{me, "catalog.infrapi.io", "apiregistrations", "get", "network.infrapi.io", false},
		{me, "catalog.infrapi.io", "apiregistrations", "list", "", false},
		{me, "authorization.infrapi.io", "apiregistrations", "get", "compute.infrapi.io", false},
		{"jdoe", "catalog.infrapi.io", "apiregistrations", "get", "compute.infrapi.io", false},
		{"system:serviceaccount:core:compute.infrapi.io", "catalog.infrapi.io", "apiregistrations", "get", "compute.infrapi.io", false},
	} {
		if got := ImplicitAPI(c.caller, c.api, c.resource, c.verb, c.name); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
}

// An API is a member of a group naming it in apis, exactly, never through
// users, groups or a wildcard.
func TestGroupMatchesAPI(t *testing.T) {
	const me = "system:api:compute.infrapi.io"
	for _, c := range []struct {
		g    Group
		want bool
	}{
		{Group{APIs: []string{"compute.infrapi.io"}}, true},
		{Group{Metadata: Metadata{Namespace: "core"}, APIs: []string{"compute.infrapi.io"}}, true},
		{Group{APIs: []string{"network.infrapi.io"}}, false},
		{Group{Users: []string{"*"}, Groups: []string{"*"}}, false},
		{Group{Users: []string{me}}, false},
		{Group{Groups: []string{"system:apis"}}, false},
	} {
		if got := groupMatchesCaller(c.g, me, []string{"system:apis"}); got != c.want {
			t.Errorf("%+v: %v", c.g, got)
		}
	}
	if groupMatchesCaller(Group{Users: []string{"*"}}, "system:other", nil) {
		t.Error("another reserved subject matched by a wildcard")
	}
}
