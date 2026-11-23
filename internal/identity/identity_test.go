package identity

import "testing"

func TestServiceAccount(t *testing.T) {
	sub := ServiceAccount("core", "deployer")
	if sub != "system:serviceaccount:core:deployer" || !IsReserved(sub) || IsReserved("jdoe") {
		t.Fatalf("subject %q", sub)
	}
	if ns, name, ok := ParseServiceAccount(sub); !ok || ns != "core" || name != "deployer" {
		t.Fatalf("parse: %q %q %v", ns, name, ok)
	}
	for _, s := range []string{"jdoe", "system:serviceaccount:core", "system:serviceaccount:core:", "system:serviceaccount:Core:x", "system:serviceaccount:a:b:c", "system:api:compute.infrapi.io"} {
		if _, _, ok := ParseServiceAccount(s); ok {
			t.Errorf("%q parsed as a service account", s)
		}
	}
	if g := ServiceAccountGroups("core"); len(g) != 2 || g[0] != "system:serviceaccounts" || g[1] != "system:serviceaccounts:core" {
		t.Fatalf("groups %v", g)
	}
}
