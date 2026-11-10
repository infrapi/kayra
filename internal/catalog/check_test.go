package catalog

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/middleware"
	"github.com/infrapi/kayra/internal/rbac"
	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

func TestApiNameForms(t *testing.T) {
	long := map[string]bool{
		"compute.example.com": true,
		"dev.giservices.io":   true,
		"compute":             false,
		"Compute.example.com": false,
		".example.com":        false,
		"compute..com":        false,
	}
	for name, want := range long {
		if got := IsLongApiName(name); got != want {
			t.Errorf("IsLongApiName(%q) = %v, want %v", name, got, want)
		}
	}
	short := map[string]bool{
		"compute":             true,
		"dev-1":               true,
		"compute.example.com": false,
		"-dev":                false,
		"":                    false,
	}
	for name, want := range short {
		if got := IsShortApiName(name); got != want {
			t.Errorf("IsShortApiName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestCheckNamespace(t *testing.T) {
	repo := newTestRepo(t)
	if err := repo.PutNamespace(&Namespace{Name: "core"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.CheckNamespace("core"); err != nil {
		t.Fatalf("existing namespace: %v", err)
	}
	if err := repo.CheckNamespace("nope"); err == nil || err.Code != http.StatusNotFound {
		t.Fatalf("missing namespace: %v, want 404", err)
	}
}

func TestCheckApiSubscription(t *testing.T) {
	repo := newTestRepo(t)
	for _, ns := range []string{"core", "other", "pending", "failed", "behind"} {
		if err := repo.PutNamespace(&Namespace{Name: ns}); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.PutClusterApiRegistration(&ApiRegistration{Name: "compute.example.com", ShortName: "compute", Platform: testDeployPlatform, Region: testDeployRegion, SyncID: "v2"}); err != nil {
		t.Fatal(err)
	}
	// Registered elsewhere only: must not count as existing here.
	if err := repo.PutClusterApiRegistration(&ApiRegistration{Name: "dns.example.com", Platform: "prod", Region: testDeployRegion}); err != nil {
		t.Fatal(err)
	}
	subs := map[string]Subscription{
		"core":    {ApiName: "compute.example.com", Active: true, State: SubscriptionStateSuccess, CurrentSyncID: "v2"},
		"pending": {ApiName: "compute.example.com", State: SubscriptionStateInit},
		"failed":  {ApiName: "compute.example.com", State: SubscriptionStateError},
		// Active but one sync behind (v1 vs v2), and the last re-sync
		// failed: a v1 api stays backward compatible, so still usable.
		"behind": {ApiName: "compute.example.com", Active: true, State: SubscriptionStateError, CurrentSyncID: "v1"},
	}
	for ns, sub := range subs {
		sub := sub
		if err := repo.PutNamespaceSubscription(ns, &sub); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		desc, namespace, api string
		wantCode             int    // 0 means no error
		wantInSolution       string // checked when non-empty
	}{
		{"active and synced", "core", "compute.example.com", 0, ""},
		{"active, out of date, last sync failed", "behind", "compute.example.com", 0, ""},
		{"short name is not an id", "core", "compute", http.StatusNotFound, `long name "compute.example.com"`},
		{"api not registered", "core", "vault.example.com", http.StatusNotFound, ""},
		{"api registered in another platform", "core", "dns.example.com", http.StatusNotFound, ""},
		{"namespace not subscribed", "other", "compute.example.com", http.StatusForbidden, "subscribe first"},
		{"inactive: initial sync pending", "pending", "compute.example.com", http.StatusForbidden, "wait for the initial sync"},
		{"inactive: initial sync failed", "failed", "compute.example.com", http.StatusForbidden, "re-sync"},
	}
	for _, tc := range cases {
		err := repo.CheckApiSubscription(tc.namespace, tc.api, testDeployPlatform, testDeployRegion)
		switch {
		case tc.wantCode == 0 && err != nil:
			t.Errorf("%s: unexpected error %v", tc.desc, err)
		case tc.wantCode != 0 && err == nil:
			t.Errorf("%s: no error, want %d", tc.desc, tc.wantCode)
		case tc.wantCode != 0 && err.Code != tc.wantCode:
			t.Errorf("%s: code %d, want %d (%v)", tc.desc, err.Code, tc.wantCode, err)
		case tc.wantInSolution != "" && !strings.Contains(err.Solution, tc.wantInSolution):
			t.Errorf("%s: solution %q, want it to mention %q", tc.desc, err.Solution, tc.wantInSolution)
		}
	}
}

// TestCheckRouteOrder drives POST .../check through the real catalog
// and rbac steps, wired exactly as apiserver.Build wires them, adding
// one missing piece of setup per case: each case's answer must be the
// first step that still fails, never a later one. This is the reported
// case — listing "dashboards" on "telemetry.giservices.io" in "core" —
// walked through every step.
func TestCheckRouteOrder(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	keys := store.NewKeys("")
	catalogRepo := NewRepository(s, keys)
	rbacRepo := rbac.NewRepository(s, keys)

	const (
		ns    = "core"
		api   = "telemetry.giservices.io"
		group = "core-devs"
	)
	engine := gin.New()
	rbac.RegisterAuthorizeRoute(engine, rbacRepo, func(c *gin.Context) {
		middleware.SetAuth(c, &middleware.AuthContext{UserID: "alice", Groups: []string{group}})
		c.Next()
	}, rbac.Prechecks{
		Namespace: catalogRepo.CheckNamespace,
		Api: func(namespace, api string) *liberrors.Error {
			return catalogRepo.CheckApiSubscription(namespace, api, testDeployPlatform, testDeployRegion)
		},
		Resource: func(api, resource, verb string) *liberrors.Error {
			return catalogRepo.CheckApiResource(api, resource, verb, testDeployPlatform, testDeployRegion)
		},
	})

	resource := "dashboards"
	check := func(verb string) (int, string) {
		body := `{"namespace":"` + ns + `","api":"` + api + `","resource":"` + resource + `","verb":"` + verb + `"}`
		req := httptest.NewRequest(http.MethodPost, "/apis/"+rbac.AuthorizationAPI+"/v1/check", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	meta := rbac.Metadata{Namespace: ns}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	steps := []struct {
		desc     string
		setup    func()
		verb     string
		wantCode int
		want     string // substring of the body
	}{
		{"1 namespace missing", func() {}, "list", http.StatusNotFound, `namespace \"core\" not found`},
		{"2 not a member", func() { must(catalogRepo.PutNamespace(&Namespace{Name: ns})) }, "list", http.StatusOK, `you are not a member of namespace \"core\"`},
		{"3 api not registered", func() {
			must(rbacRepo.PutNamespaceGroup(ns, &rbac.Group{Name: "devs", Metadata: meta, Groups: []string{group}}))
		}, "list", http.StatusNotFound, `api \"telemetry.giservices.io\" is not registered`},
		{"4 not subscribed", func() {
			must(catalogRepo.PutClusterApiRegistration(&ApiRegistration{Name: api, Platform: testDeployPlatform, Region: testDeployRegion, SyncID: "v1"}))
		}, "list", http.StatusForbidden, "subscribe first"},
		{"5 subscription not active blocks reads too", func() {
			must(catalogRepo.PutNamespaceSubscription(ns, &Subscription{ApiName: api, State: SubscriptionStateInit}))
		}, "list", http.StatusForbidden, "is not active yet"},
		{"6 resource not served (singular typo)", func() {
			must(catalogRepo.ActivateSubscription(ns, api, "v1"))
			must(catalogRepo.PutApiSpec(testDeployPlatform, testDeployRegion, &ApiSpec{Api: api, SyncID: "v1",
				Resources: []ApiResource{{Name: "dashboards", Namespaced: true, Verbs: []string{"get", "list"}}}}))
			resource = "dashboard"
		}, "list", http.StatusNotFound, `did you mean \"dashboards\"`},
		{"7 verb not supported", func() { resource = "dashboards" }, "delete", http.StatusMethodNotAllowed, `doesn't support \"delete\" (supported: get, list)`},
		{"8 no role grants the api", func() {
			must(rbacRepo.PutNamespaceRole(ns, &rbac.Role{Name: "compute-reader", Metadata: meta,
				Rules: []rbac.Rule{{Apis: []string{"compute.example.com"}, Resources: []string{"*"}, Verbs: []string{"*"}}}}))
			must(rbacRepo.PutNamespaceRoleBinding(ns, &rbac.RoleBinding{Name: "devs-compute", Metadata: meta, Role: "compute-reader", Groups: []string{"devs"}}))
		}, "list", http.StatusOK, `no role bound to your groups in namespace \"core\" grants api \"telemetry.giservices.io\"`},
		{"9 api granted but not this verb", func() {
			must(rbacRepo.PutNamespaceRole(ns, &rbac.Role{Name: "telemetry-reader", Metadata: meta,
				Rules: []rbac.Rule{{Apis: []string{api}, Resources: []string{"dashboards"}, Verbs: []string{"get"}}}}))
			must(rbacRepo.PutNamespaceRoleBinding(ns, &rbac.RoleBinding{Name: "devs-telemetry", Metadata: meta, Role: "telemetry-reader", Groups: []string{"devs"}}))
		}, "list", http.StatusOK, `grant api \"telemetry.giservices.io\", but not \"list\" on \"dashboards\"`},
		{"allowed", func() {}, "get", http.StatusOK, `"allowed":true`},
		{"allowed while out of date", func() {
			reg, err := catalogRepo.GetClusterApiRegistration(testDeployPlatform, testDeployRegion, api)
			must(err)
			reg.SyncID = "v2"
			must(catalogRepo.PutClusterApiRegistration(&reg))
		}, "get", http.StatusOK, `"allowed":true`},
	}
	for _, st := range steps {
		st.setup()
		code, body := check(st.verb)
		if code != st.wantCode || !strings.Contains(body, st.want) {
			t.Fatalf("%s: status %d body %s, want %d containing %s", st.desc, code, body, st.wantCode, st.want)
		}
	}
}

func TestCheckApiResource(t *testing.T) {
	repo := newTestRepo(t)
	const api = "telemetry.giservices.io"
	if err := repo.PutApiSpec(testDeployPlatform, testDeployRegion, &ApiSpec{Api: api, SyncID: "v1", Resources: []ApiResource{
		{Name: "dashboards", Namespaced: true, Verbs: []string{"get", "list"}},
		{Name: "dashboards/refresh", Namespaced: true, Verbs: []string{"patch"}},
		{Name: "datasources", Namespaced: false, Verbs: []string{"list"}},
	}}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		desc, api, resource, verb string
		wantCode                  int
		wantIn                    string // in detail or solution
	}{
		{"served", api, "dashboards", "list", 0, ""},
		{"action", api, "dashboards/refresh", "patch", 0, ""},
		{"unknown resource", api, "panels", "list", http.StatusNotFound, "kayra-cli apis"},
		{"singular typo", api, "dashboard", "list", http.StatusNotFound, `did you mean "dashboards"`},
		{"cluster-scoped resource", api, "datasources", "list", http.StatusNotFound, "cluster-scoped"},
		{"verb not supported", api, "dashboards", "delete", http.StatusMethodNotAllowed, "supported: get, list"},
		{"no spec stored", "vault.example.com", "secrets", "get", http.StatusServiceUnavailable, "sync_id"},
	}
	for _, tc := range cases {
		err := repo.CheckApiResource(tc.api, tc.resource, tc.verb, testDeployPlatform, testDeployRegion)
		switch {
		case tc.wantCode == 0 && err != nil:
			t.Errorf("%s: unexpected error %v", tc.desc, err)
		case tc.wantCode != 0 && err == nil:
			t.Errorf("%s: no error, want %d", tc.desc, tc.wantCode)
		case tc.wantCode != 0 && err.Code != tc.wantCode:
			t.Errorf("%s: code %d, want %d (%v)", tc.desc, err.Code, tc.wantCode, err)
		case tc.wantCode != 0 && !strings.Contains(err.Message+" "+err.Solution, tc.wantIn):
			t.Errorf("%s: %v, want it to mention %q", tc.desc, err, tc.wantIn)
		}
	}
}

func TestValidateRoleRules(t *testing.T) {
	repo := newTestRepo(t)
	for _, name := range []string{"telemetry.giservices.io", "vault.example.com"} {
		if err := repo.PutClusterApiRegistration(&ApiRegistration{Name: name, Platform: testDeployPlatform, Region: testDeployRegion}); err != nil {
			t.Fatal(err)
		}
	}
	// telemetry has a spec; vault was never synced, so it has none.
	if err := repo.PutApiSpec(testDeployPlatform, testDeployRegion, &ApiSpec{Api: "telemetry.giservices.io", Resources: []ApiResource{
		{Name: "dashboards", Namespaced: true, Verbs: []string{"get", "list"}},
		{Name: "dashboards/refresh", Namespaced: true, Verbs: []string{"patch"}},
	}}); err != nil {
		t.Fatal(err)
	}
	rule := func(api string, resources, verbs []string) []rbac.Rule {
		return []rbac.Rule{{Apis: []string{api}, Resources: resources, Verbs: verbs}}
	}
	cases := []struct {
		desc   string
		rules  []rbac.Rule
		wantIn string // "" means valid
	}{
		{"valid", rule("telemetry.giservices.io", []string{"dashboards"}, []string{"get", "list"}), ""},
		{"verb served by another of the rule's resources", rule("telemetry.giservices.io", []string{"dashboards", "dashboards/refresh"}, []string{"list", "patch"}), ""},
		{"wildcards", rule("telemetry.giservices.io", []string{"*"}, []string{"*"}), ""},
		{"wildcard api", rule("*", []string{"anything"}, []string{"anything"}), ""},
		{"kayra's own api", rule(CatalogAPI, []string{"subscriptions"}, []string{"list"}), ""},
		{"api without a spec yet", rule("vault.example.com", []string{"secrets"}, []string{"get"}), ""},
		{"unregistered api", rule("nope.example.com", []string{"x"}, []string{"get"}), "is not registered"},
		{"short name", rule("telemetry", []string{"dashboards"}, []string{"get"}), "is not registered"},
		{"unknown resource", rule("telemetry.giservices.io", []string{"dashboard"}, []string{"get"}), `did you mean "dashboards"`},
		{"unsupported verb", rule("telemetry.giservices.io", []string{"dashboards"}, []string{"delete"}), `supports "delete"`},
		{"wildcard resource, unsupported verb", rule("telemetry.giservices.io", []string{"*"}, []string{"delete"}), `supports "delete"`},
	}
	for _, tc := range cases {
		err := repo.ValidateRoleRules(tc.rules, testDeployPlatform, testDeployRegion)
		switch {
		case tc.wantIn == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.desc, err)
		case tc.wantIn != "" && err == nil:
			t.Errorf("%s: accepted, want an error mentioning %q", tc.desc, tc.wantIn)
		case tc.wantIn != "" && (err.Code != http.StatusBadRequest || !strings.Contains(err.Message+" "+err.Solution, tc.wantIn)):
			t.Errorf("%s: %v, want a 400 mentioning %q", tc.desc, err, tc.wantIn)
		}
	}
}
