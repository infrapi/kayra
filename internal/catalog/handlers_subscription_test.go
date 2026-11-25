package catalog

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/rbac"
	"github.com/infrapi/kayra/internal/store"
)

func TestNamespaceSubscriptionCRUD(t *testing.T) {
	engine, repo := newTestEngine(t)
	ns := testNamespace

	doJSON(t, engine, http.MethodPost, "/apis/catalog.infrapi.io/v1/apiregistrations", ApiRegistration{Name: "vault.infrapi.io", Platform: testDeployPlatform, Region: testDeployRegion, Active: true})

	// active/state are computed: there is no request field that can make
	// a subscription come back anything but disabled/init.
	w := doJSON(t, engine, http.MethodPost, "/apis/catalog.infrapi.io/v1/namespaces/"+ns+"/subscriptions", subscriptionCreateRequest{
		ApiName: "vault.infrapi.io",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: status %d, body %s", w.Code, w.Body.String())
	}
	var created Subscription
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if created.State != SubscriptionStateInit || created.Active {
		t.Fatalf("created = %+v, want disabled/init", created)
	}

	w = doJSON(t, engine, http.MethodGet, "/apis/catalog.infrapi.io/v1/namespaces/"+ns+"/subscriptions", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: status %d, body %s", w.Code, w.Body.String())
	}
	var subs []Subscription
	if err := json.Unmarshal(w.Body.Bytes(), &subs); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("list = %v, want 1 entry", subs)
	}

	w = doJSON(t, engine, http.MethodGet, "/apis/catalog.infrapi.io/v1/namespaces/"+ns+"/subscriptions/vault.infrapi.io", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: status %d, body %s", w.Code, w.Body.String())
	}

	// only the internal activation path can flip it — not any HTTP route.
	if err := repo.ActivateSubscription(ns, "vault.infrapi.io", "sync-1"); err != nil {
		t.Fatalf("ActivateSubscription: %v", err)
	}
	w = doJSON(t, engine, http.MethodGet, "/apis/catalog.infrapi.io/v1/namespaces/"+ns+"/subscriptions/vault.infrapi.io", nil)
	var activated Subscription
	if err := json.Unmarshal(w.Body.Bytes(), &activated); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if activated.State != SubscriptionStateSuccess || !activated.Active || activated.CurrentSyncID != "sync-1" {
		t.Fatalf("get after ActivateSubscription = %+v, want active/success/sync-1", activated)
	}

	w = doJSON(t, engine, http.MethodDelete, "/apis/catalog.infrapi.io/v1/namespaces/"+ns+"/subscriptions/vault.infrapi.io", nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d, body %s", w.Code, w.Body.String())
	}
	w = doJSON(t, engine, http.MethodGet, "/apis/catalog.infrapi.io/v1/namespaces/"+ns+"/subscriptions/vault.infrapi.io", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("get after delete: status %d, want 404", w.Code)
	}
}

// TestSubscriptionResponseComputesExpectedSyncID confirms expected_sync_id
// is never stored on the subscription itself: it's the referenced api
// registration's own, current SyncID, read fresh on every response —
// so it moves the instant the registration's SyncID does, with no
// Reconciler pass required,
// while current_sync_id (the subscription's own persisted field) only
// moves once something actually reconciles it.
func TestSubscriptionResponseComputesExpectedSyncID(t *testing.T) {
	engine, repo := newTestEngine(t)
	ns := testNamespace

	if err := repo.PutClusterApiRegistration(&ApiRegistration{
		Name: "vault.infrapi.io", Platform: testDeployPlatform, Region: testDeployRegion,
		Active: true, SyncID: "api-sync-1",
	}); err != nil {
		t.Fatalf("PutClusterApiRegistration: %v", err)
	}
	if err := repo.PutNamespaceSubscription(ns, &Subscription{ApiName: "vault.infrapi.io", State: SubscriptionStateInit}); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}

	get := func() subscriptionResponse {
		t.Helper()
		w := doJSON(t, engine, http.MethodGet, "/apis/catalog.infrapi.io/v1/namespaces/"+ns+"/subscriptions/vault.infrapi.io", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("get: status %d, body %s", w.Code, w.Body.String())
		}
		var resp subscriptionResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		return resp
	}

	// not yet activated: current_sync_id is empty, but expected_sync_id
	// already reflects the api registration — the two visibly differ.
	resp := get()
	if resp.CurrentSyncID != "" || resp.ExpectedSyncID != "api-sync-1" || resp.Synced {
		t.Fatalf("pre-activation = %+v, want current=\"\" expected=api-sync-1 synced=false", resp)
	}

	// activated and reconciled to the api registration's current SyncID: the two match.
	if err := repo.ActivateSubscription(ns, "vault.infrapi.io", "api-sync-1"); err != nil {
		t.Fatalf("ActivateSubscription: %v", err)
	}
	resp = get()
	if resp.CurrentSyncID != "api-sync-1" || resp.ExpectedSyncID != "api-sync-1" || !resp.Synced {
		t.Fatalf("post-activation = %+v, want both api-sync-1 and synced=true", resp)
	}

	// the api registration's SyncID moves on: expected_sync_id follows immediately
	// (computed fresh), current_sync_id does not (nothing reconciled it).
	if err := repo.PutClusterApiRegistration(&ApiRegistration{
		Name: "vault.infrapi.io", Platform: testDeployPlatform, Region: testDeployRegion,
		Active: true, SyncID: "api-sync-2",
	}); err != nil {
		t.Fatalf("PutClusterApiRegistration (bump sync_id): %v", err)
	}
	resp = get()
	if resp.CurrentSyncID != "api-sync-1" || resp.ExpectedSyncID != "api-sync-2" || resp.Synced {
		t.Fatalf("post-bump = %+v, want current=api-sync-1 expected=api-sync-2 synced=false (reconcile pending)", resp)
	}
}

// TestSubscriptionForceSync confirms PUT .../sync does exactly one
// thing — reset CurrentSyncID to empty — leaving Active/State untouched,
// so an already-active subscription is left active but visibly
// unreconciled (current_sync_id "" != expected_sync_id), for Reconciler to
// pick up and reconcile again on its own.
func TestSubscriptionForceSync(t *testing.T) {
	engine, repo := newTestEngine(t)
	ns := testNamespace

	if err := repo.PutClusterApiRegistration(&ApiRegistration{
		Name: "vault.infrapi.io", Platform: testDeployPlatform, Region: testDeployRegion,
		Active: true, SyncID: "api-sync-1",
	}); err != nil {
		t.Fatalf("PutClusterApiRegistration: %v", err)
	}
	if err := repo.PutNamespaceSubscription(ns, &Subscription{ApiName: "vault.infrapi.io", State: SubscriptionStateInit}); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}
	if err := repo.ActivateSubscription(ns, "vault.infrapi.io", "api-sync-1"); err != nil {
		t.Fatalf("ActivateSubscription: %v", err)
	}

	w := doJSON(t, engine, http.MethodPut, "/apis/catalog.infrapi.io/v1/namespaces/"+ns+"/subscriptions/vault.infrapi.io/sync", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("sync: status %d, body %s", w.Code, w.Body.String())
	}
	var resp subscriptionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if resp.CurrentSyncID != "" {
		t.Fatalf("resp.CurrentSyncID = %q, want empty after force sync", resp.CurrentSyncID)
	}
	if resp.ExpectedSyncID != "api-sync-1" {
		t.Fatalf("resp.ExpectedSyncID = %q, want api-sync-1 (unchanged)", resp.ExpectedSyncID)
	}
	if !resp.Active || resp.State != SubscriptionStateSuccess {
		t.Fatalf("resp = %+v, want Active/State untouched by force sync", resp)
	}

	sub, err := repo.GetNamespaceSubscription(ns, "vault.infrapi.io")
	if err != nil {
		t.Fatalf("GetNamespaceSubscription: %v", err)
	}
	if sub.CurrentSyncID != "" || !sub.Active || sub.State != SubscriptionStateSuccess {
		t.Fatalf("persisted sub = %+v, want current_sync_id reset, active/state untouched", sub)
	}
}

// TestSubscriptionForceSyncRequiresExistingSubscription confirms the
// sync endpoint 404s on a subscription that was never created, same as
// every other subscription route scoped by :api.
func TestSubscriptionForceSyncRequiresExistingSubscription(t *testing.T) {
	engine, _ := newTestEngine(t)

	w := doJSON(t, engine, http.MethodPut, "/apis/catalog.infrapi.io/v1/namespaces/"+testNamespace+"/subscriptions/does-not-exist/sync", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body %s", w.Code, w.Body.String())
	}
}

// TestSubscriptionResponseAlwaysIncludesSyncFields confirms
// current_sync_id/expected_sync_id are never omitted from a subscription
// response, even when both are empty — a caller should never have to
// treat "the key is missing" and "the key is empty" as two different
// things. The api registration is written directly via the repository,
// bypassing the create-registration route's own sync_id
// auto-generation (Server.CreateAPIRegistration), to exercise a registration whose SyncID is
// still genuinely empty.
func TestSubscriptionResponseAlwaysIncludesSyncFields(t *testing.T) {
	engine, repo := newTestEngine(t)
	ns := testNamespace

	if err := repo.PutClusterApiRegistration(&ApiRegistration{Name: "vault.infrapi.io", Platform: testDeployPlatform, Region: testDeployRegion, Active: true}); err != nil {
		t.Fatalf("PutClusterApiRegistration: %v", err)
	}
	w := doJSON(t, engine, http.MethodPost, "/apis/catalog.infrapi.io/v1/namespaces/"+ns+"/subscriptions", subscriptionCreateRequest{ApiName: "vault.infrapi.io"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: status %d, body %s", w.Code, w.Body.String())
	}

	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{"current_sync_id", "expected_sync_id"} {
		v, ok := raw[key]
		if !ok {
			t.Fatalf("response missing key %q entirely: %v", key, raw)
		}
		if v != "" {
			t.Fatalf("response[%q] = %v, want empty string", key, v)
		}
	}
}

func TestSubscriptionCreateRejectsMissingApiRegistration(t *testing.T) {
	engine, _ := newTestEngine(t)

	w := doJSON(t, engine, http.MethodPost, "/apis/catalog.infrapi.io/v1/namespaces/"+testNamespace+"/subscriptions", Subscription{
		ApiName: "does-not-exist.infrapi.io",
	})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body %s", w.Code, w.Body.String())
	}
}

// TestSubscriptionOnlyMatchesApiRegistrationInDeploymentScope confirms
// an api registration that exists, but in a different platform/region
// than this deployment's own, is treated as not found by a
// subscription — there is no way for a bare registration name to mean
// anything else.
func TestSubscriptionOnlyMatchesApiRegistrationInDeploymentScope(t *testing.T) {
	engine, repo := newTestEngine(t)

	if err := repo.PutClusterApiRegistration(&ApiRegistration{Name: "vault.infrapi.io", Platform: "other-platform", Region: "other-region", Active: true}); err != nil {
		t.Fatalf("PutClusterApiRegistration: %v", err)
	}

	w := doJSON(t, engine, http.MethodPost, "/apis/catalog.infrapi.io/v1/namespaces/"+testNamespace+"/subscriptions", Subscription{
		ApiName: "vault.infrapi.io",
	})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (api registration exists, but not in this deployment's platform/region), body %s", w.Code, w.Body.String())
	}
}

// TestSubscriptionCreateIgnoresClientActiveAndState confirms active/state
// aren't part of what POST binds at all: a client can't force either one,
// valid or not, through the request body — the subscription always comes
// back disabled/init.
func TestSubscriptionCreateIgnoresClientActiveAndState(t *testing.T) {
	engine, _ := newTestEngine(t)

	doJSON(t, engine, http.MethodPost, "/apis/catalog.infrapi.io/v1/apiregistrations", ApiRegistration{Name: "vault.infrapi.io", Platform: testDeployPlatform, Region: testDeployRegion, Active: true})

	w := doJSON(t, engine, http.MethodPost, "/apis/catalog.infrapi.io/v1/namespaces/"+testNamespace+"/subscriptions", Subscription{
		ApiName: "vault.infrapi.io", Active: true, State: "bogus",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (active/state are ignored, not bound from the request), body %s", w.Code, w.Body.String())
	}
	var created Subscription
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if created.State != SubscriptionStateInit || created.Active {
		t.Fatalf("created = %+v, want disabled/init regardless of request body", created)
	}
}

func TestSubscriptionRequiresClusterRBAC(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer func() { _ = s.Close() }()
	keys := store.NewKeys("")

	repo := NewRepository(s, keys)
	rbacRepo := rbac.NewRepository(s, keys)
	if err := repo.PutClusterApiRegistration(&ApiRegistration{Name: "vault.infrapi.io", Platform: testDeployPlatform, Region: testDeployRegion, Active: true}); err != nil {
		t.Fatalf("PutClusterApiRegistration: %v", err)
	}

	engine := gin.New()
	mount(engine, repo, rbacRepo, fakeAuthGate("nobody"))

	w := doJSON(t, engine, http.MethodPost, "/apis/catalog.infrapi.io/v1/namespaces/myns/subscriptions", Subscription{
		ApiName: "vault.infrapi.io",
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body %s", w.Code, w.Body.String())
	}
}

// TestSubscriptionSyncIsGatedOnItsOwnResource confirms PUT .../sync is
// checked against resource "subscriptions/sync", verb patch, distinct
// from "subscriptions" — so a role granting "subscriptions"/"update" alone
// does not also grant the sync action.
func TestSubscriptionSyncIsGatedOnItsOwnResource(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer func() { _ = s.Close() }()
	keys := store.NewKeys("")

	repo := NewRepository(s, keys)
	rbacRepo := rbac.NewRepository(s, keys)
	if err := repo.PutClusterApiRegistration(&ApiRegistration{Name: "vault.infrapi.io", Platform: testDeployPlatform, Region: testDeployRegion, Active: true, SyncID: "sync-1"}); err != nil {
		t.Fatalf("PutClusterApiRegistration: %v", err)
	}
	if err := repo.PutNamespaceSubscription(testNamespace, &Subscription{ApiName: "vault.infrapi.io"}); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}
	if err := repo.ActivateSubscription(testNamespace, "vault.infrapi.io", "sync-1"); err != nil {
		t.Fatalf("ActivateSubscription: %v", err)
	}

	meta := rbac.Metadata{Namespace: testNamespace}
	if err := rbacRepo.PutClusterGroup(&rbac.Group{
		Name: "g", Metadata: meta,
		Groups: []string{testAdminGroup},
	}); err != nil {
		t.Fatalf("PutClusterGroup: %v", err)
	}
	// Grants resource "subscriptions"/"update" only — not the sync
	// action's own "subscriptions/sync" resource.
	if err := rbacRepo.PutClusterRole(&rbac.Role{
		Name: "r", Metadata: meta,
		Rules: []rbac.Rule{{Apis: []string{CatalogAPI}, Resources: []string{"subscriptions"}, Verbs: []string{"update"}}},
	}); err != nil {
		t.Fatalf("PutClusterRole: %v", err)
	}
	if err := rbacRepo.PutClusterRoleBinding(&rbac.RoleBinding{
		Name: "rb", Metadata: meta, Role: "r", Groups: []string{"g"},
	}); err != nil {
		t.Fatalf("PutClusterRoleBinding: %v", err)
	}

	engine := gin.New()
	mount(engine, repo, rbacRepo, fakeAuthGate(testAdmin, testAdminGroup))

	w := doJSON(t, engine, http.MethodPut, "/apis/catalog.infrapi.io/v1/namespaces/"+testNamespace+"/subscriptions/vault.infrapi.io/sync", nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf(`PUT sync: status = %d, want 403 (role grants "subscriptions" only, not "subscriptions/sync"), body %s`, w.Code, w.Body.String())
	}
}
