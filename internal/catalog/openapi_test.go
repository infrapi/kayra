package catalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/config"
)

// testGatewayURL is a fake gateway every test Reconciler is pointed at
// (the spec is mandatory, so no sync completes without one): it serves a
// minimal valid spec for any /apis/<api>/-/openapi.json.
var testGatewayURL string

func TestMain(m *testing.M) {
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/apis/") || !strings.HasSuffix(r.URL.Path, "/-/openapi.json") {
			http.NotFound(w, r)
			return
		}
		api := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/apis/"), "/-/openapi.json")
		_, _ = w.Write([]byte(`{"openapi":"3.1.0","paths":{"/apis/` + api + `/v1/namespaces/{namespace}/things":{"get":{}}}}`))
	}))
	testGatewayURL = gw.URL
	code := m.Run()
	gw.Close()
	os.Exit(code)
}

func TestDeriveResources(t *testing.T) {
	routes := []Route{
		// OpenAPI-style params, as an app's spec has them.
		{"GET", "/apis/telemetry.giservices.io/v1/namespaces/{namespace}/dashboards"},
		{"POST", "/apis/telemetry.giservices.io/v1/namespaces/{namespace}/dashboards"},
		{"GET", "/apis/telemetry.giservices.io/v1/namespaces/{namespace}/dashboards/{name}"},
		{"DELETE", "/apis/telemetry.giservices.io/v1/namespaces/{namespace}/dashboards/{name}"},
		{"PATCH", "/apis/telemetry.giservices.io/v1/namespaces/{namespace}/dashboards/{name}/refresh"},
		// gin-style params, as Kayra's own route table has them.
		{"GET", "/apis/telemetry.giservices.io/v1/datasources"},
		{"PUT", "/apis/telemetry.giservices.io/v1/datasources/:name"},
		// "namespaces" itself is a cluster-scoped resource.
		{"GET", "/apis/telemetry.giservices.io/v1/namespaces/:namespace"},
		// Not this api's: ignored.
		{"GET", "/apis/other.example.com/v1/things"},
		{"GET", "/-/healthz"},
	}
	got := DeriveResources("telemetry.giservices.io", routes)
	want := []ApiResource{
		{Name: "dashboards", Namespaced: true, Verbs: []string{"create", "delete", "get", "list"}},
		{Name: "dashboards/refresh", Namespaced: true, Verbs: []string{"patch"}},
		{Name: "datasources", Namespaced: false, Verbs: []string{"list", "update"}},
		{Name: "namespaces", Namespaced: false, Verbs: []string{"get"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DeriveResources =\n%+v\nwant\n%+v", got, want)
	}
}

func TestFetchSpec(t *testing.T) {
	var body atomic.Value
	var status atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/compute.example.com/-/openapi.json" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write(body.Load().([]byte))
	}))
	defer srv.Close()
	ctx := context.Background()

	status.Store(200)
	body.Store([]byte(`{"openapi": "3.1.0", "paths": {"/apis/compute.example.com/v1/namespaces/{namespace}/vms": {"get": {}}}}`))
	spec, err := FetchSpec(ctx, srv.Client(), srv.URL+"/", "compute.example.com")
	if err != nil {
		t.Fatalf("FetchSpec: %v", err)
	}
	if spec.URL != srv.URL+"/apis/compute.example.com/-/openapi.json" || len(spec.Resources) != 1 || spec.Resources[0].Name != "vms" {
		t.Fatalf("spec = %+v", spec)
	}
	if !json.Valid(spec.Spec) || strings.Contains(string(spec.Spec), " ") {
		t.Fatalf("stored spec should be the compacted document, got %s", spec.Spec)
	}

	for desc, tc := range map[string]struct {
		status  int32
		body    string
		gateway string
	}{
		"no gateway configured": {200, `{}`, "-"},
		"non-200":               {503, `{}`, ""},
		"not JSON":              {200, `<html>`, ""},
		"not OpenAPI":           {200, `{"swagger":"2.0"}`, ""},
		"too large":             {200, `{"openapi":"3.1.0","paths":{},"x":"` + strings.Repeat("a", MaxSpecBytes) + `"}`, ""},
	} {
		status.Store(tc.status)
		body.Store([]byte(tc.body))
		gw := srv.URL
		if tc.gateway == "-" {
			gw = ""
		}
		if _, err := FetchSpec(ctx, srv.Client(), gw, "compute.example.com"); err == nil {
			t.Errorf("%s: FetchSpec succeeded, want an error", desc)
		}
	}
}

// TestReconcilerStoresSpecOnSyncAndBlocksWithoutIt covers the spec's
// lifecycle in the Reconciler: fetched once for a registration's
// sync_id even with no subscriber, refetched when sync_id moves, and
// mandatory — a sync whose spec can't be fetched doesn't activate the
// subscription.
func TestReconcilerStoresSpecOnSyncAndBlocksWithoutIt(t *testing.T) {
	var fetches atomic.Int32
	var failing atomic.Bool
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		if failing.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"openapi":"3.1.0","paths":{"/apis/vault.example.com/v1/namespaces/{namespace}/secrets":{"get":{},"post":{}}}}`))
	}))
	defer gw.Close()

	repo := newTestRepo(t)
	reg := ApiRegistration{Name: "vault.example.com", Platform: testDeployPlatform, Region: testDeployRegion, Active: true, SyncID: "sync-1", Mode: "trigger"}
	if err := repo.PutClusterApiRegistration(&reg); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: gw.URL}).Run(ctx)
	}()

	waitFor(t, func() bool {
		spec, err := repo.GetApiSpec(testDeployPlatform, testDeployRegion, reg.Name)
		return err == nil && spec.SyncID == "sync-1" && len(spec.Resources) == 1 && spec.Resources[0].Name == "secrets"
	}, "spec stored for sync-1 with no subscriber")

	// A subscription syncs to sync-1 with the stored spec: no refetch.
	before := fetches.Load()
	if err := repo.PutNamespaceSubscription("myns", &Subscription{ApiName: reg.Name, State: SubscriptionStateInit}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		sub, err := repo.GetNamespaceSubscription("myns", reg.Name)
		return err == nil && sub.Active
	}, "subscription activated")
	if fetches.Load() != before {
		t.Fatalf("spec refetched for an unchanged sync_id (%d -> %d fetches)", before, fetches.Load())
	}

	// sync-2 with the app's spec unreachable: the subscription must not move.
	failing.Store(true)
	reg.SyncID = "sync-2"
	if err := repo.PutClusterApiRegistration(&reg); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		sub, err := repo.GetNamespaceSubscription("myns", reg.Name)
		return err == nil && sub.State == SubscriptionStateError
	}, "subscription marked error when the spec can't be fetched")
	time.Sleep(200 * time.Millisecond)
	if sub, _ := repo.GetNamespaceSubscription("myns", reg.Name); sub.CurrentSyncID != "sync-1" {
		t.Fatalf("current_sync_id = %q, want sync-1 kept (spec is mandatory)", sub.CurrentSyncID)
	}

	// Spec reachable again and the registration touched: sync-2 completes.
	failing.Store(false)
	if err := repo.PutClusterApiRegistration(&reg); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		sub, err1 := repo.GetNamespaceSubscription("myns", reg.Name)
		spec, err2 := repo.GetApiSpec(testDeployPlatform, testDeployRegion, reg.Name)
		return err1 == nil && err2 == nil && sub.CurrentSyncID == "sync-2" && sub.State == SubscriptionStateSuccess && spec.SyncID == "sync-2"
	}, "sync-2 completes once the spec is fetched")

	// Deleting the registration deletes its spec.
	if err := repo.DeleteClusterApiRegistration(testDeployPlatform, testDeployRegion, reg.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetApiSpec(testDeployPlatform, testDeployRegion, reg.Name); err == nil {
		t.Fatalf("spec still stored after the registration was deleted")
	}
}

// TestDiscoveryRoutes covers GET /apis for registered apps (resources
// from the stored spec, scoped to this platform/region, empty until the
// first fetch) and GET .../apiregistrations/{name}/openapi.json.
func TestDiscoveryRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := newTestRepo(t)
	for _, reg := range []ApiRegistration{
		{Name: "telemetry.giservices.io", ShortName: "telemetry", Owner: "obs", Platform: testDeployPlatform, Region: testDeployRegion, SyncID: "s2"},
		{Name: "vault.example.com", Owner: "sre", Platform: testDeployPlatform, Region: testDeployRegion},
		{Name: "dns.example.com", Platform: "prod", Region: testDeployRegion}, // another platform: not listed
	} {
		reg := reg
		if err := repo.PutClusterApiRegistration(&reg); err != nil {
			t.Fatal(err)
		}
	}
	doc := `{"openapi":"3.1.0","paths":{"/apis/telemetry.giservices.io/v1/namespaces/{namespace}/dashboards":{"get":{}}}}`
	if err := repo.PutApiSpec(testDeployPlatform, testDeployRegion, &ApiSpec{
		Api: "telemetry.giservices.io", SyncID: "s1", Spec: json.RawMessage(doc),
		Resources: []ApiResource{{Name: "dashboards", Namespaced: true, Verbs: []string{"list"}}},
	}); err != nil {
		t.Fatal(err)
	}

	engine := gin.New()
	builtin := func() []Route {
		return []Route{{Method: "GET", Path: "/apis/" + CatalogAPI + "/v1/apiregistrations"}}
	}
	RegisterDiscoveryRoutes(engine, repo, func(c *gin.Context) { c.Next() }, builtin, testDeployPlatform, testDeployRegion)

	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}

	w := get("/apis")
	var groups []DiscoveryGroup
	if err := json.Unmarshal(w.Body.Bytes(), &groups); err != nil || w.Code != http.StatusOK {
		t.Fatalf("GET /apis: status %d, err %v, body %s", w.Code, err, w.Body.String())
	}
	var names []string
	for _, g := range groups {
		names = append(names, g.Api)
	}
	if got := strings.Join(names, ","); got != CatalogAPI+",telemetry.giservices.io,vault.example.com" {
		t.Fatalf("groups = %s, want Kayra's own first, then this platform/region's registrations by name", got)
	}
	if !groups[0].Builtin || groups[0].Owner != "kayra" {
		t.Fatalf("builtin group = %+v", groups[0])
	}
	tel := groups[1]
	if tel.ShortName != "telemetry" || tel.SyncID != "s2" || tel.SpecSyncID != "s1" || len(tel.Resources) != 1 || tel.Resources[0].Name != "dashboards" {
		t.Fatalf("telemetry group = %+v", tel)
	}
	if v := groups[2]; v.SpecSyncID != "" || v.Resources == nil || len(v.Resources) != 0 {
		t.Fatalf("vault (no spec yet) = %+v, want resources [] and no spec_sync_id", v)
	}

	w = get("/apis/" + CatalogAPI + "/v1/apiregistrations/telemetry.giservices.io/openapi.json")
	if w.Code != http.StatusOK || w.Body.String() != doc || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("openapi.json: status %d, type %q, body %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	if w = get("/apis/" + CatalogAPI + "/v1/apiregistrations/vault.example.com/openapi.json"); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "next sync") {
		t.Fatalf("openapi.json before any fetch: status %d, body %s", w.Code, w.Body.String())
	}
	if w = get("/apis/" + CatalogAPI + "/v1/apiregistrations/nope.example.com/openapi.json"); w.Code != http.StatusNotFound {
		t.Fatalf("openapi.json of an unknown registration: status %d", w.Code)
	}
}
