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

func TestFederatedCredentialMatches(t *testing.T) {
	claims := map[string]any{"sub": "repo:example/compute:environment:prod", "repository": "example/compute", "ref_protected": true, "run": float64(42), "groups": []any{"a"}}
	for _, tt := range []struct {
		f    FederatedCredential
		want bool
	}{
		{FederatedCredential{Subject: "repo:example/compute:environment:prod"}, true},
		{FederatedCredential{Subject: "repo:example/compute:environment:dev"}, false},
		{FederatedCredential{Claims: map[string]string{"repository": "example/compute", "ref_protected": "true", "run": "42"}}, true},
		{FederatedCredential{Claims: map[string]string{"ref_protected": "false"}}, false},
		{FederatedCredential{Claims: map[string]string{"missing": "x"}}, false},
		{FederatedCredential{Claims: map[string]string{"groups": "a"}}, false},
		{FederatedCredential{Subject: "repo:example/compute:environment:prod", Claims: map[string]string{"repository": "other"}}, false},
		{FederatedCredential{}, false},
	} {
		if got := tt.f.Matches(claims); got != tt.want {
			t.Errorf("%+v: %v, want %v", tt.f, got, tt.want)
		}
	}
}
