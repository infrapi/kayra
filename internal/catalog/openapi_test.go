package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/infrapi/kayra/internal/store"
)

// testGatewayURL is a fake gateway every test Reconciler is pointed at
// (the spec is mandatory, so no sync completes without one): it serves a
// minimal valid spec for any /apis/<api>/<version>/-/openapi.json.
var testGatewayURL string

func TestMain(m *testing.M) {
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/apis/") || !strings.HasSuffix(r.URL.Path, "/-/openapi.json") {
			http.NotFound(w, r)
			return
		}
		root := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/apis/"), "/-/openapi.json") // <api>/<version>
		_, _ = w.Write([]byte(`{"openapi":"3.1.0","paths":{"/apis/` + root + `/namespaces/{namespace}/things":{"get":{}}}}`))
	}))
	testGatewayURL = gw.URL
	code := m.Run()
	gw.Close()
	os.Exit(code)
}

func TestDeriveResources(t *testing.T) {
	routes := []Route{
		// OpenAPI-style params, as an app's spec has them.
		{"GET", "/apis/telemetry.infrapi.io/v1/namespaces/{namespace}/dashboards"},
		{"POST", "/apis/telemetry.infrapi.io/v1/namespaces/{namespace}/dashboards"},
		{"GET", "/apis/telemetry.infrapi.io/v1/namespaces/{namespace}/dashboards/{name}"},
		{"DELETE", "/apis/telemetry.infrapi.io/v1/namespaces/{namespace}/dashboards/{name}"},
		{"PATCH", "/apis/telemetry.infrapi.io/v1/namespaces/{namespace}/dashboards/{name}/refresh"},
		// a collection under an item: listed, as infrapi/lib asks
		{"GET", "/apis/telemetry.infrapi.io/v1/namespaces/{namespace}/dashboards/{name}/panels"},
		{"GET", "/apis/telemetry.infrapi.io/v1/namespaces/{namespace}/dashboards/{name}/panels/{panel}"},
		// gin-style params, as Kayra's own route table has them.
		{"GET", "/apis/telemetry.infrapi.io/v1/datasources"},
		{"PUT", "/apis/telemetry.infrapi.io/v1/datasources/:name"},
		// "namespaces" itself is a cluster-scoped resource.
		{"GET", "/apis/telemetry.infrapi.io/v1/namespaces/:namespace"},
		// The app's own operational endpoints, under its root: ignored.
		{"GET", "/apis/telemetry.infrapi.io/v1/-/healthz"},
		{"GET", "/apis/telemetry.infrapi.io/v1/-/openapi/telemetry/v1.yaml"},
		// Not this api's, or not this version's: ignored.
		{"GET", "/apis/other.infrapi.io/v1/things"},
		{"GET", "/apis/telemetry.infrapi.io/v2/widgets"},
		{"GET", "/-/healthz"},
	}
	got := DeriveResources("telemetry.infrapi.io", "v1", routes)
	want := []ApiResource{
		{Name: "dashboards", Namespaced: true, Verbs: []string{"create", "delete", "get", "list"}},
		{Name: "dashboards/panels", Namespaced: true, Verbs: []string{"get", "list"}},
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
		if r.URL.Path != "/apis/compute.infrapi.io/v2beta1/-/openapi.json" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write(body.Load().([]byte))
	}))
	defer srv.Close()
	ctx := context.Background()

	status.Store(200)
	body.Store([]byte(`{"openapi": "3.1.0", "paths": {"/apis/compute.infrapi.io/v2beta1/namespaces/{namespace}/vms": {"get": {}}}}`))
	spec, err := FetchSpec(ctx, srv.Client(), srv.URL+"/", "compute.infrapi.io", "v2beta1")
	if err != nil {
		t.Fatalf("FetchSpec: %v", err)
	}
	if spec.URL != srv.URL+"/apis/compute.infrapi.io/v2beta1/-/openapi.json" || spec.Version != "v2beta1" ||
		len(spec.Resources) != 1 || spec.Resources[0].Name != "vms" {
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
		if _, err := FetchSpec(ctx, srv.Client(), gw, "compute.infrapi.io", "v2beta1"); err == nil {
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
		_, _ = w.Write([]byte(`{"openapi":"3.1.0","paths":{"/apis/vault.infrapi.io/v1/namespaces/{namespace}/secrets":{"get":{},"post":{}}}}`))
	}))
	defer gw.Close()

	repo := newTestRepo(t)
	reg := ApiRegistration{Name: "vault.infrapi.io", Platform: testDeployPlatform, Region: testDeployRegion, Active: true, SyncID: "sync-1", Mode: "trigger"}
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

// TestReconcilerFetchesIdentityKeys: an identity with jwks_from spec, the
// app's public keys fetched with its spec at each sync, and the client
// they make (ApiClient); no keys served, no spec stored.
func TestReconcilerFetchesIdentityKeys(t *testing.T) {
	var keys atomic.Value
	keys.Store(`{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","x":"QpKqxqA4mEU2hmEoj-cdvR6XBuNOe5IL_CwjWS0x3-4","y":"d8MxKfIUkWL13JxESClUvVdBZVKBUKoD2cW6uKVDn_Q"}]}`)
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/apis/compute.infrapi.io/v1/-/openapi.json":
			_, _ = w.Write([]byte(`{"openapi":"3.1.0","paths":{"/apis/compute.infrapi.io/v1/namespaces/{namespace}/vms":{"get":{}}}}`))
		case "/apis/compute.infrapi.io/v1/-/jwks.json":
			switch k := keys.Load().(string); k {
			case "":
			case "401":
				w.WriteHeader(http.StatusUnauthorized)
				return
			default:
				_, _ = w.Write([]byte(k))
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer gw.Close()

	repo := newTestRepo(t)
	reg := ApiRegistration{Name: "compute.infrapi.io", Platform: testDeployPlatform, Region: testDeployRegion, SyncID: "sync-1", UID: "u1",
		Identity: &ApiIdentity{JWKSFrom: JWKSFromSpec}}
	if err := repo.PutClusterApiRegistration(&reg); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: gw.URL}).Run(ctx)
	}()
	waitFor(t, func() bool {
		uid, k, _, err := repo.ApiClient(testDeployPlatform, testDeployRegion, reg.Name)
		return err == nil && uid == "u1" && len(k) == 1 && k[0].Kid == "k1"
	}, "its keys, from its spec")

	// rotated: the new key served, a sync
	keys.Store(`{"keys":[{"kty":"EC","crv":"P-256","kid":"k2","x":"QpKqxqA4mEU2hmEoj-cdvR6XBuNOe5IL_CwjWS0x3-4","y":"d8MxKfIUkWL13JxESClUvVdBZVKBUKoD2cW6uKVDn_Q"}]}`)
	reg.SyncID = "sync-2"
	if err := repo.PutClusterApiRegistration(&reg); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		_, k, _, err := repo.ApiClient(testDeployPlatform, testDeployRegion, reg.Name)
		return err == nil && len(k) == 1 && k[0].Kid == "k2"
	}, "the new key after a sync")

	// none served: no keys, no token
	keys.Store("")
	reg.SyncID = "sync-3"
	if err := repo.PutClusterApiRegistration(&reg); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		_, k, _, err := repo.ApiClient(testDeployPlatform, testDeployRegion, reg.Name)
		return err == nil && len(k) == 0
	}, "no keys when it serves none")

	// an empty set, or an app answering 401 (no open route): no keys either
	for i, none := range []string{`{"keys":[]}`, "401"} {
		keys.Store(none)
		reg.SyncID = fmt.Sprintf("sync-none-%d", i)
		if err := repo.PutClusterApiRegistration(&reg); err != nil {
			t.Fatal(err)
		}
		waitFor(t, func() bool {
			spec, err := repo.GetApiSpec(testDeployPlatform, testDeployRegion, reg.Name)
			return err == nil && spec.SyncID == reg.SyncID && spec.JWKS != nil && len(spec.JWKS.Keys) == 0
		}, "no keys: "+none)
	}
	sync3 := reg.SyncID

	// a private key: sync-4's spec is not stored
	for i, bad := range []string{`{"keys":[{"kty":"EC","crv":"P-256","x":"QpKqxqA4mEU2hmEoj-cdvR6XBuNOe5IL_CwjWS0x3-4","y":"d8MxKfIUkWL13JxESClUvVdBZVKBUKoD2cW6uKVDn_Q","d":"x"}]}`} {
		keys.Store(bad)
		reg.SyncID = fmt.Sprintf("sync-4-%d", i)
		if err := repo.PutClusterApiRegistration(&reg); err != nil {
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
		if spec, _ := repo.GetApiSpec(testDeployPlatform, testDeployRegion, reg.Name); spec.SyncID != sync3 {
			t.Errorf("%q: spec of %s stored", bad, spec.SyncID)
		}
	}

	// no identity: no client
	if err := repo.PutClusterApiRegistration(&ApiRegistration{Name: "vault.infrapi.io", Platform: testDeployPlatform, Region: testDeployRegion}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := repo.ApiClient(testDeployPlatform, testDeployRegion, "vault.infrapi.io"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("no identity: %v", err)
	}
}

// TestDiscoveryRoutes covers GET /apis for registered apps (resources
// from the stored spec, scoped to this platform/region, empty until the
// first fetch) and GET .../apiregistrations/{name}/openapi.json.
func TestDiscoveryRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := newTestRepo(t)
	for _, reg := range []ApiRegistration{
		{Name: "telemetry.infrapi.io", ShortName: "telemetry", Owner: "obs", Platform: testDeployPlatform, Region: testDeployRegion, SyncID: "s2"},
		{Name: "vault.infrapi.io", Owner: "sre", Platform: testDeployPlatform, Region: testDeployRegion},
		{Name: "dns.infrapi.io", Platform: "prod", Region: testDeployRegion}, // another platform: not listed
	} {
		reg := reg
		if err := repo.PutClusterApiRegistration(&reg); err != nil {
			t.Fatal(err)
		}
	}
	doc := `{"openapi":"3.1.0","paths":{"/apis/telemetry.infrapi.io/v1/namespaces/{namespace}/dashboards":{"get":{}}}}`
	if err := repo.PutApiSpec(testDeployPlatform, testDeployRegion, &ApiSpec{
		Api: "telemetry.infrapi.io", SyncID: "s1", Spec: json.RawMessage(doc),
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
	if got := strings.Join(names, ","); got != CatalogAPI+",telemetry.infrapi.io,vault.infrapi.io" {
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

	w = get("/apis/" + CatalogAPI + "/v1/apiregistrations/telemetry.infrapi.io/openapi.json")
	if w.Code != http.StatusOK || w.Body.String() != doc || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("openapi.json: status %d, type %q, body %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	if w = get("/apis/" + CatalogAPI + "/v1/apiregistrations/vault.infrapi.io/openapi.json"); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "next sync") {
		t.Fatalf("openapi.json before any fetch: status %d, body %s", w.Code, w.Body.String())
	}
	if w = get("/apis/" + CatalogAPI + "/v1/apiregistrations/nope.infrapi.io/openapi.json"); w.Code != http.StatusNotFound {
		t.Fatalf("openapi.json of an unknown registration: status %d", w.Code)
	}
}
