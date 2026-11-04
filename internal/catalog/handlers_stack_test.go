package catalog

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestClusterStackCRUD(t *testing.T) {
	engine, _ := newTestEngine(t)

	w := doJSON(t, engine, http.MethodPost, "/apis/catalog.example.com/v1/stacks", Stack{
		Name: "vault", Active: true, Owner: "sre-a",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: status %d, body %s", w.Code, w.Body.String())
	}

	w = doJSON(t, engine, http.MethodGet, "/apis/catalog.example.com/v1/stacks", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: status %d, body %s", w.Code, w.Body.String())
	}
	var stacks []Stack
	if err := json.Unmarshal(w.Body.Bytes(), &stacks); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(stacks) != 1 || stacks[0].Name != "vault" {
		t.Fatalf("list = %v, want [vault]", stacks)
	}

	w = doJSON(t, engine, http.MethodGet, "/apis/catalog.example.com/v1/stacks/vault", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: status %d, body %s", w.Code, w.Body.String())
	}

	w = doJSON(t, engine, http.MethodGet, "/apis/catalog.example.com/v1/stacks/missing", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("get missing: status %d, want 404", w.Code)
	}

	w = doJSON(t, engine, http.MethodPut, "/apis/catalog.example.com/v1/stacks/vault", Stack{Owner: "sre-b", Active: true})
	if w.Code != http.StatusOK {
		t.Fatalf("update: status %d, body %s", w.Code, w.Body.String())
	}
	var updated Stack
	if err := json.Unmarshal(w.Body.Bytes(), &updated); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if updated.Owner != "sre-b" || updated.Name != "vault" {
		t.Fatalf("update response = %+v", updated)
	}

	w = doJSON(t, engine, http.MethodPut, "/apis/catalog.example.com/v1/stacks/missing", Stack{Active: true})
	if w.Code != http.StatusNotFound {
		t.Fatalf("update missing: status %d, want 404", w.Code)
	}

	w = doJSON(t, engine, http.MethodDelete, "/apis/catalog.example.com/v1/stacks/vault", nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d, body %s", w.Code, w.Body.String())
	}
	w = doJSON(t, engine, http.MethodDelete, "/apis/catalog.example.com/v1/stacks/vault", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("delete missing: status %d, want 404", w.Code)
	}
}

// TestStackSync confirms PUT .../sync stamps a fresh, non-empty UUID each
// time it's called, and that an explicit sync_id is still settable
// through the normal stack update endpoint.
func TestStackSync(t *testing.T) {
	engine, _ := newTestEngine(t)

	doJSON(t, engine, http.MethodPost, "/apis/catalog.example.com/v1/stacks", Stack{Name: "vault", Active: true})

	w := doJSON(t, engine, http.MethodPut, "/apis/catalog.example.com/v1/stacks/vault/sync", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("sync: status %d, body %s", w.Code, w.Body.String())
	}
	var first Stack
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if first.SyncID == "" {
		t.Fatalf("sync response = %+v, want a non-empty sync_id", first)
	}

	w = doJSON(t, engine, http.MethodPut, "/apis/catalog.example.com/v1/stacks/vault/sync", nil)
	var second Stack
	if err := json.Unmarshal(w.Body.Bytes(), &second); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if second.SyncID == "" || second.SyncID == first.SyncID {
		t.Fatalf("second sync_id = %q, want a different non-empty value from %q", second.SyncID, first.SyncID)
	}

	// an explicit sync_id is still settable through the normal update.
	w = doJSON(t, engine, http.MethodPut, "/apis/catalog.example.com/v1/stacks/vault", Stack{SyncID: "custom-id"})
	var explicit Stack
	if err := json.Unmarshal(w.Body.Bytes(), &explicit); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if explicit.SyncID != "custom-id" {
		t.Fatalf("explicit update sync_id = %q, want %q", explicit.SyncID, "custom-id")
	}

	w = doJSON(t, engine, http.MethodPut, "/apis/catalog.example.com/v1/stacks/missing/sync", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("sync missing stack: status %d, want 404", w.Code)
	}
}

// TestStackCreateGeneratesDefaultSyncID confirms a stack created with no
// explicit sync_id is given one automatically — Reconciler never
// reconciles a stack whose SyncID is empty (see
// TestReconcilerSkipsSubscriptionWhenStackSyncIDEmpty), so a freshly
// kickstarted stack needs one from the start rather than waiting on a
// manual PUT .../sync. An explicit sync_id in the request is still
// honored as-is.
func TestStackCreateGeneratesDefaultSyncID(t *testing.T) {
	engine, _ := newTestEngine(t)

	w := doJSON(t, engine, http.MethodPost, "/apis/catalog.example.com/v1/stacks", Stack{Name: "vault", Active: true})
	var created Stack
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if created.SyncID == "" {
		t.Fatalf("created.SyncID is empty, want a generated default")
	}

	w = doJSON(t, engine, http.MethodPost, "/apis/catalog.example.com/v1/stacks", Stack{Name: "pki", Active: true, SyncID: "explicit-id"})
	var explicit Stack
	if err := json.Unmarshal(w.Body.Bytes(), &explicit); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if explicit.SyncID != "explicit-id" {
		t.Fatalf("explicit.SyncID = %q, want %q (caller-supplied value kept)", explicit.SyncID, "explicit-id")
	}
}

// TestStackStatus confirms GET .../status reports the stack's own
// current sync_id plus every active subscription's sync state against
// it, skipping subscriptions still pending the initial activation.
func TestStackStatus(t *testing.T) {
	engine, repo := newTestEngine(t)

	doJSON(t, engine, http.MethodPost, "/apis/catalog.example.com/v1/stacks", Stack{Name: "vault", Active: true})
	stack, err := repo.GetClusterStack(testDeployPlatform, testDeployRegion, "vault")
	if err != nil {
		t.Fatalf("GetClusterStack: %v", err)
	}

	if err := repo.PutNamespaceSubscription("synced-ns", Subscription{
		StackName: "vault", Active: true, State: SubscriptionStateSuccess, CurrentSyncID: stack.SyncID,
	}); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}
	if err := repo.PutNamespaceSubscription("stale-ns", Subscription{
		StackName: "vault", Active: true, State: SubscriptionStateSuccess, CurrentSyncID: "old-sync-id",
	}); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}
	if err := repo.PutNamespaceSubscription("pending-ns", Subscription{
		StackName: "vault", State: SubscriptionStateInit,
	}); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}

	w := doJSON(t, engine, http.MethodGet, "/apis/catalog.example.com/v1/stacks/vault/status", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status: status %d, body %s", w.Code, w.Body.String())
	}
	var resp stackStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if resp.StackName != "vault" || resp.SyncID != stack.SyncID {
		t.Fatalf("resp = %+v, want stack_name=vault sync_id=%q", resp, stack.SyncID)
	}
	if len(resp.Subscriptions) != 2 {
		t.Fatalf("resp.Subscriptions = %+v, want 2 entries (pending-ns excluded)", resp.Subscriptions)
	}
	// sorted by namespace: "stale-ns" sorts before "synced-ns".
	if resp.Subscriptions[0].Namespace != "stale-ns" || resp.Subscriptions[0].Synced {
		t.Fatalf("resp.Subscriptions[0] = %+v, want stale-ns/unsynced", resp.Subscriptions[0])
	}
	if resp.Subscriptions[1].Namespace != "synced-ns" || !resp.Subscriptions[1].Synced {
		t.Fatalf("resp.Subscriptions[1] = %+v, want synced-ns/synced", resp.Subscriptions[1])
	}

	w = doJSON(t, engine, http.MethodGet, "/apis/catalog.example.com/v1/stacks/missing/status", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status missing stack: status %d, want 404", w.Code)
	}
}

// TestStackSyncCanaryRollout confirms the two-step canary workflow: a
// sync naming canary_namespaces mints a fresh sync_id but only restricts
// Reconciler's fan-out to those namespaces (see TestReconcilerHandleStackPutRespectsCanaryNamespaces
// for the Reconciler-side half of this); a later release sync (no
// canary_namespaces) reuses that exact sync_id rather than minting
// another, and clears the restriction.
func TestStackSyncCanaryRollout(t *testing.T) {
	engine, repo := newTestEngine(t)

	doJSON(t, engine, http.MethodPost, "/apis/catalog.example.com/v1/stacks", Stack{Name: "vault", Active: true})
	if err := repo.PutNamespaceSubscription("canary-ns", Subscription{StackName: "vault", State: SubscriptionStateInit}); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}

	w := doJSON(t, engine, http.MethodPut, "/apis/catalog.example.com/v1/stacks/vault/sync", map[string]any{
		"canary_namespaces": []string{"canary-ns"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("canary sync: status %d, body %s", w.Code, w.Body.String())
	}
	var canaried Stack
	if err := json.Unmarshal(w.Body.Bytes(), &canaried); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if canaried.SyncID == "" {
		t.Fatalf("canaried = %+v, want a non-empty sync_id", canaried)
	}
	if len(canaried.CanaryNamespaces) != 1 || canaried.CanaryNamespaces[0] != "canary-ns" {
		t.Fatalf("canaried.CanaryNamespaces = %v, want [canary-ns]", canaried.CanaryNamespaces)
	}

	// a namespace that isn't actually subscribed is rejected outright,
	// rather than silently accepted as a canary target that can never
	// be reconciled.
	w = doJSON(t, engine, http.MethodPut, "/apis/catalog.example.com/v1/stacks/vault/sync", map[string]any{
		"canary_namespaces": []string{"not-subscribed"},
	})
	if w.Code != http.StatusNotFound {
		t.Fatalf("canary sync with unsubscribed namespace: status %d, want 404, body %s", w.Code, w.Body.String())
	}

	// an unrelated full-stack edit mid-rollout (the general PUT is a full
	// replace, so a realistic caller still names every field it wants
	// kept, sync_id included) must not touch the pending canary
	// restriction — that one field is never settable through this route
	// at all, unlike every other field here.
	w = doJSON(t, engine, http.MethodPut, "/apis/catalog.example.com/v1/stacks/vault", Stack{Active: true, Owner: "sre", SyncID: canaried.SyncID})
	var midRollout Stack
	if err := json.Unmarshal(w.Body.Bytes(), &midRollout); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(midRollout.CanaryNamespaces) != 1 || midRollout.CanaryNamespaces[0] != "canary-ns" {
		t.Fatalf("mid-rollout update = %+v, want canary_namespaces left untouched", midRollout)
	}

	// release: no canary_namespaces named, and a rollout is pending, so
	// this reuses the already-canaried sync_id rather than minting a new
	// one, and clears the restriction.
	w = doJSON(t, engine, http.MethodPut, "/apis/catalog.example.com/v1/stacks/vault/sync", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("release sync: status %d, body %s", w.Code, w.Body.String())
	}
	var released Stack
	if err := json.Unmarshal(w.Body.Bytes(), &released); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if released.SyncID != canaried.SyncID {
		t.Fatalf("released.SyncID = %q, want the same as the canary's %q", released.SyncID, canaried.SyncID)
	}
	if len(released.CanaryNamespaces) != 0 {
		t.Fatalf("released.CanaryNamespaces = %v, want empty (restriction lifted)", released.CanaryNamespaces)
	}

	// with no rollout pending, a plain sync goes back to minting a fresh
	// sync_id, exactly like before canary existed at all.
	w = doJSON(t, engine, http.MethodPut, "/apis/catalog.example.com/v1/stacks/vault/sync", nil)
	var ordinary Stack
	if err := json.Unmarshal(w.Body.Bytes(), &ordinary); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if ordinary.SyncID == "" || ordinary.SyncID == released.SyncID {
		t.Fatalf("ordinary sync_id = %q, want a fresh value distinct from %q", ordinary.SyncID, released.SyncID)
	}
}

// TestStackRoutesAreScopedToDeployment confirms platform/region are never
// taken from the request: create always stamps this deployment's own
// (overriding whatever a client sends), and the list/get/update/delete
// routes can only ever reach a stack in that same scope — a stack
// belonging to another platform/region, even with the same name, is
// invisible to all of them.
func TestStackRoutesAreScopedToDeployment(t *testing.T) {
	engine, repo := newTestEngine(t)

	// a client-supplied platform/region is silently overridden.
	w := doJSON(t, engine, http.MethodPost, "/apis/catalog.example.com/v1/stacks", Stack{
		Name: "vault", Platform: "some-other-platform", Region: "some-other-region",
	})
	var created Stack
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if created.Platform != testDeployPlatform || created.Region != testDeployRegion {
		t.Fatalf("created = %+v, want this deployment's own platform/region", created)
	}

	// a same-named stack in a foreign platform/region, written directly
	// (bypassing HTTP, as a sibling deployment sharing the same store
	// would), must not show up in this instance's list or be reachable
	// by name.
	if err := repo.PutClusterStack(Stack{Name: "vault", Platform: "other-platform", Region: "other-region"}); err != nil {
		t.Fatalf("PutClusterStack: %v", err)
	}

	w = doJSON(t, engine, http.MethodGet, "/apis/catalog.example.com/v1/stacks", nil)
	var stacks []Stack
	if err := json.Unmarshal(w.Body.Bytes(), &stacks); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(stacks) != 1 {
		t.Fatalf("list = %v, want exactly the one stack in this deployment's own scope", stacks)
	}
}

func TestStackCreateRejectsMissingDependsOn(t *testing.T) {
	engine, _ := newTestEngine(t)

	w := doJSON(t, engine, http.MethodPost, "/apis/catalog.example.com/v1/stacks", Stack{
		Name: "pki", Active: true,
		DependsOn: []StackRef{{Platform: testDeployPlatform, Region: testDeployRegion, Name: "vault"}},
	})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (vault does not exist yet), body %s", w.Code, w.Body.String())
	}
}

func TestStackDeleteBlockedWhileDependedOn(t *testing.T) {
	engine, _ := newTestEngine(t)

	doJSON(t, engine, http.MethodPost, "/apis/catalog.example.com/v1/stacks", Stack{Name: "vault", Active: true})
	doJSON(t, engine, http.MethodPost, "/apis/catalog.example.com/v1/stacks", Stack{
		Name: "pki", Active: true,
		DependsOn: []StackRef{{Platform: testDeployPlatform, Region: testDeployRegion, Name: "vault"}},
	})

	w := doJSON(t, engine, http.MethodDelete, "/apis/catalog.example.com/v1/stacks/vault", nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("delete depended-on stack: status %d, want 409, body %s", w.Code, w.Body.String())
	}

	// deleting the dependent stack first, then the dependency, works.
	w = doJSON(t, engine, http.MethodDelete, "/apis/catalog.example.com/v1/stacks/pki", nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete pki: status %d, body %s", w.Code, w.Body.String())
	}
	w = doJSON(t, engine, http.MethodDelete, "/apis/catalog.example.com/v1/stacks/vault", nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete vault after pki removed: status %d, body %s", w.Code, w.Body.String())
	}
}

func TestStackDeleteBlockedWhileSubscribedTo(t *testing.T) {
	engine, _ := newTestEngine(t)

	doJSON(t, engine, http.MethodPost, "/apis/catalog.example.com/v1/stacks", Stack{Name: "vault", Active: true})
	w := doJSON(t, engine, http.MethodPost, "/apis/subscription.example.com/v1/namespaces/"+testNamespace+"/subscriptions", Subscription{
		StackName: "vault",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create subscription: status %d, body %s", w.Code, w.Body.String())
	}

	w = doJSON(t, engine, http.MethodDelete, "/apis/catalog.example.com/v1/stacks/vault", nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("delete subscribed-to stack: status %d, want 409, body %s", w.Code, w.Body.String())
	}
}
