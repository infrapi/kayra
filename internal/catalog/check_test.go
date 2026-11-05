package catalog

import (
	"net/http"
	"testing"
)

func TestApiNameFromURN(t *testing.T) {
	cases := map[string]struct {
		name string
		ok   bool
	}{
		"compute.example.com":   {"compute", true},
		"compute.other.com":     {"", false},
		"a.compute.example.com": {"", false},
		".example.com":          {"", false},
		"example.com":           {"", false},
		"compute":               {"", false},
	}
	for urn, want := range cases {
		name, ok := ApiNameFromURN(urn)
		if name != want.name || ok != want.ok {
			t.Errorf("ApiNameFromURN(%q) = (%q, %v), want (%q, %v)", urn, name, ok, want.name, want.ok)
		}
	}
}

func TestCheckSubscribedApi(t *testing.T) {
	repo := newTestRepo(t)
	if err := repo.PutNamespace(Namespace{Name: "core"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.PutNamespace(Namespace{Name: "other"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.PutClusterApiRegistration(ApiRegistration{Name: "compute", Platform: testDeployPlatform, Region: testDeployRegion}); err != nil {
		t.Fatal(err)
	}
	// Registered elsewhere only: must not count as existing here.
	if err := repo.PutClusterApiRegistration(ApiRegistration{Name: "dns", Platform: "prod", Region: testDeployRegion}); err != nil {
		t.Fatal(err)
	}
	if err := repo.PutNamespaceSubscription("core", Subscription{ApiName: "compute", Active: true, State: SubscriptionStateSuccess}); err != nil {
		t.Fatal(err)
	}
	// Subscribed but never reconciled: read-only.
	if err := repo.PutNamespace(Namespace{Name: "pending"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.PutNamespaceSubscription("pending", Subscription{ApiName: "compute", State: SubscriptionStateInit}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		desc, namespace, api, verb string
		wantCode                   int // 0 means no error
	}{
		{"active, read", "core", "compute.example.com", "list", 0},
		{"active, write", "core", "compute.example.com", "create", 0},
		{"namespace missing", "nope", "compute.example.com", "get", http.StatusNotFound},
		{"api outside domain", "core", "compute.other.com", "get", http.StatusNotFound},
		{"api not registered", "core", "vault.example.com", "get", http.StatusNotFound},
		{"api registered in another platform", "core", "dns.example.com", "get", http.StatusNotFound},
		{"namespace not subscribed", "other", "compute.example.com", "get", http.StatusForbidden},
		{"inactive, get", "pending", "compute.example.com", "get", 0},
		{"inactive, list", "pending", "compute.example.com", "list", 0},
		{"inactive, create", "pending", "compute.example.com", "create", http.StatusForbidden},
		{"inactive, update", "pending", "compute.example.com", "update", http.StatusForbidden},
		{"inactive, patch", "pending", "compute.example.com", "patch", http.StatusForbidden},
		{"inactive, delete", "pending", "compute.example.com", "delete", http.StatusForbidden},
		{"inactive, unknown verb", "pending", "compute.example.com", "reboot", http.StatusForbidden},
	}
	for _, tc := range cases {
		err := repo.CheckSubscribedApi(tc.namespace, tc.api, tc.verb, testDeployPlatform, testDeployRegion)
		switch {
		case tc.wantCode == 0 && err != nil:
			t.Errorf("%s: unexpected error %v", tc.desc, err)
		case tc.wantCode != 0 && err == nil:
			t.Errorf("%s: no error, want %d", tc.desc, tc.wantCode)
		case tc.wantCode != 0 && err.Code != tc.wantCode:
			t.Errorf("%s: code %d, want %d (%v)", tc.desc, err.Code, tc.wantCode, err)
		}
	}
}
