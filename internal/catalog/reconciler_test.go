package catalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/infrapi/kayra/internal/config"
	"github.com/infrapi/kayra/internal/store"
)

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return data
}

func TestReconcilerActivatesNewNamespace(t *testing.T) {
	repo := newTestRepo(t)

	if err := repo.PutNamespace(&Namespace{Name: "core"}); err != nil {
		t.Fatalf("PutNamespace: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL, MaxConcurrentReconciles: 0, DefaultMode: ""}).Run(ctx)
	}()

	waitFor(t, func() bool {
		n, err := repo.GetNamespace("core")
		return err == nil && n.Active
	}, "namespace core to become active")
}

func TestReconcilerActivatesNewSubscription(t *testing.T) {
	repo := newTestRepo(t)

	if err := repo.PutClusterApiRegistration(&ApiRegistration{
		Name: "vault", Platform: testDeployPlatform, Region: testDeployRegion, Active: true,
		SyncID: "sync-1", Mode: "trigger",
	}); err != nil {
		t.Fatalf("PutClusterApiRegistration: %v", err)
	}
	if err := repo.PutNamespaceSubscription("myns", &Subscription{ApiName: "vault", State: SubscriptionStateInit}); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL, MaxConcurrentReconciles: 0, DefaultMode: ""}).Run(ctx)
	}()

	waitFor(t, func() bool {
		sub, err := repo.GetNamespaceSubscription("myns", "vault")
		return err == nil && sub.Active && sub.State == SubscriptionStateSuccess
	}, "subscription myns/vault to become active/success")

	// the initial activation stamps the subscription's CurrentSyncID with
	// the reg's SyncID at the time it was first seen.
	sub, err := repo.GetNamespaceSubscription("myns", "vault")
	if err != nil {
		t.Fatalf("GetNamespaceSubscription: %v", err)
	}
	if sub.CurrentSyncID != "sync-1" {
		t.Fatalf("sub.CurrentSyncID = %q, want %q", sub.CurrentSyncID, "sync-1")
	}
}

// TestReconcilerIgnoresAlreadyActiveRecords confirms the Reconciler's own
// write (ActivateNamespace/ActivateSubscription) never causes it to loop
// back and act again — it would see its own Put event come through the
// same watch.
func TestReconcilerIgnoresAlreadyActiveRecords(t *testing.T) {
	repo := newTestRepo(t)

	if err := repo.PutNamespace(&Namespace{Name: "core", Active: true}); err != nil {
		t.Fatalf("PutNamespace: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL, MaxConcurrentReconciles: 0, DefaultMode: ""}).Run(ctx)
	}()

	// give the reconciler a few poll cycles to (not) do anything, then
	// confirm the record is untouched.
	time.Sleep(500 * time.Millisecond)
	n, err := repo.GetNamespace("core")
	if err != nil {
		t.Fatalf("GetNamespace: %v", err)
	}
	if !n.Active {
		t.Fatalf("GetNamespace = %+v, want still active", n)
	}
}

// TestReconcilerReconcilesActiveSubscriptionOnApiRegistrationSyncIDChange confirms
// bumping a reg's SyncID (a plain admin PUT, no separate endpoint) is
// the entire reconcile trigger: every namespace already actively
// subscribed to it gets its own SyncID updated to match, with Active left
// untouched.
func TestReconcilerReconcilesActiveSubscriptionOnApiRegistrationSyncIDChange(t *testing.T) {
	repo := newTestRepo(t)

	reg := ApiRegistration{
		Name: "vault", Platform: testDeployPlatform, Region: testDeployRegion, Active: true,
		SyncID: "sync-1", Mode: "api",
	}
	if err := repo.PutClusterApiRegistration(&reg); err != nil {
		t.Fatalf("PutClusterApiRegistration: %v", err)
	}
	if err := repo.PutNamespaceSubscription("myns", &Subscription{
		ApiName: "vault", Active: true, State: SubscriptionStateSuccess, CurrentSyncID: "sync-1",
	}); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL, MaxConcurrentReconciles: 0, DefaultMode: ""}).Run(ctx)
	}()

	// let the initial reconcile pass run (sub is already active/success,
	// so it must be a no-op) before bumping the reg's SyncID.
	time.Sleep(300 * time.Millisecond)

	reg.SyncID = "sync-2"
	if err := repo.PutClusterApiRegistration(&reg); err != nil {
		t.Fatalf("PutClusterApiRegistration (bump sync_id): %v", err)
	}

	waitFor(t, func() bool {
		sub, err := repo.GetNamespaceSubscription("myns", "vault")
		return err == nil && sub.CurrentSyncID == "sync-2"
	}, "subscription myns/vault to reconcile to sync-2")

	sub, err := repo.GetNamespaceSubscription("myns", "vault")
	if err != nil {
		t.Fatalf("GetNamespaceSubscription: %v", err)
	}
	if !sub.Active || sub.State != SubscriptionStateSuccess {
		t.Fatalf("sub = %+v, want Active/State untouched by reconcile", sub)
	}
}

// TestReconcilerApiRegistrationUpdateSkipsInactiveSubscriptions confirms a reg
// update never touches a subscription that isn't active yet — that one
// is left entirely to handleNewSubscription (the initial action), so it
// isn't force-reconciled to a stale SyncID before it's even been
// activated.
func TestReconcilerApiRegistrationUpdateSkipsInactiveSubscriptions(t *testing.T) {
	repo := newTestRepo(t)

	reg := ApiRegistration{
		Name: "vault", Platform: testDeployPlatform, Region: testDeployRegion, Active: true,
		SyncID: "sync-1", Mode: "trigger",
	}
	if err := repo.PutClusterApiRegistration(&reg); err != nil {
		t.Fatalf("PutClusterApiRegistration: %v", err)
	}

	// a subscription that exists but was never activated (simulating a
	// reconciler that hasn't gotten to it yet).
	if err := repo.PutNamespaceSubscription("myns", &Subscription{
		ApiName: "vault", State: SubscriptionStateInit,
	}); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}

	w := NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL, MaxConcurrentReconciles: 0, DefaultMode: ""})
	reg.SyncID = "sync-2"
	var wg sync.WaitGroup
	w.handleApiRegistrationPut(context.Background(), &wg, mustMarshal(t, reg))
	wg.Wait()

	sub, err := repo.GetNamespaceSubscription("myns", "vault")
	if err != nil {
		t.Fatalf("GetNamespaceSubscription: %v", err)
	}
	if sub.CurrentSyncID != "" || sub.Active {
		t.Fatalf("sub = %+v, want untouched (still disabled, CurrentSyncID empty)", sub)
	}
}

// TestReconcilerSkipsSubscriptionWhenApiRegistrationSyncIDEmpty confirms a reg
// with no SyncID yet never has its subscribers reconciled: reconcile
// exists to catch a subscription up to a specific SyncID, and a reg
// that was never assigned one has nothing to catch up to (see
// ensureReconciled). Once the reg is given a SyncID, the exact same
// subscription reconciles normally.
func TestReconcilerSkipsSubscriptionWhenApiRegistrationSyncIDEmpty(t *testing.T) {
	repo := newTestRepo(t)

	if err := repo.PutClusterApiRegistration(&ApiRegistration{
		Name: "vault", Platform: testDeployPlatform, Region: testDeployRegion, Active: true,
		Mode: "trigger", // SyncID deliberately left empty.
	}); err != nil {
		t.Fatalf("PutClusterApiRegistration: %v", err)
	}
	sub := Subscription{ApiName: "vault", State: SubscriptionStateInit}
	if err := repo.PutNamespaceSubscription("myns", &sub); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}

	w := NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL, MaxConcurrentReconciles: 0, DefaultMode: ""})
	w.handleNewSubscription(context.Background(), "myns", "vault", mustMarshal(t, sub), 0)

	got, err := repo.GetNamespaceSubscription("myns", "vault")
	if err != nil {
		t.Fatalf("GetNamespaceSubscription: %v", err)
	}
	if got.Active || got.CurrentSyncID != "" {
		t.Fatalf("sub = %+v, want untouched (still disabled, CurrentSyncID empty) since the reg has no sync_id yet", got)
	}

	reg, err := repo.GetClusterApiRegistration(testDeployPlatform, testDeployRegion, "vault")
	if err != nil {
		t.Fatalf("GetClusterApiRegistration: %v", err)
	}
	reg.SyncID = "sync-1"
	if err := repo.PutClusterApiRegistration(&reg); err != nil {
		t.Fatalf("PutClusterApiRegistration: %v", err)
	}
	w.handleNewSubscription(context.Background(), "myns", "vault", mustMarshal(t, sub), 0)

	got, err = repo.GetNamespaceSubscription("myns", "vault")
	if err != nil {
		t.Fatalf("GetNamespaceSubscription: %v", err)
	}
	if !got.Active || got.CurrentSyncID != "sync-1" {
		t.Fatalf("sub = %+v, want active/sync-1 now that the reg has a sync_id", got)
	}
}

// TestReconcilerHandleApiRegistrationPutRespectsCanaryNamespaces confirms a
// non-empty ApiRegistration.CanaryNamespaces restricts handleApiRegistrationPut's fan-out to
// just those namespaces: an active, unreconciled subscriber not on the
// list is left exactly as it was — pending — rather than reconciled,
// while one that is on the list reconciles normally. Clearing
// CanaryNamespaces (the release step of the canary workflow — see PUT
// .../apiregistrations/:name/sync) then lets the same fan-out reach everyone still
// behind.
func TestReconcilerHandleApiRegistrationPutRespectsCanaryNamespaces(t *testing.T) {
	repo := newTestRepo(t)

	reg := ApiRegistration{
		Name: "vault", Platform: testDeployPlatform, Region: testDeployRegion, Active: true,
		SyncID: "sync-1", Mode: "trigger",
	}
	if err := repo.PutClusterApiRegistration(&reg); err != nil {
		t.Fatalf("PutClusterApiRegistration: %v", err)
	}
	for _, ns := range []string{"canary-ns", "other-ns"} {
		if err := repo.PutNamespaceSubscription(ns, &Subscription{
			ApiName: "vault", Active: true, State: SubscriptionStateSuccess, CurrentSyncID: "sync-1",
		}); err != nil {
			t.Fatalf("PutNamespaceSubscription(%s): %v", ns, err)
		}
	}

	w := NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL})

	// bump SyncID with a canary restriction: only canary-ns should
	// reconcile. Persisted first, same as a real admin PUT would (the
	// write is what Watch delivers the event from in the first place) —
	// ensureReconciled re-reads the reg fresh once it holds the per-job
	// lock, so what's actually in the store must agree with the event
	// value handleApiRegistrationPut is handed below.
	reg.SyncID = "sync-2"
	reg.CanaryNamespaces = []string{"canary-ns"}
	if err := repo.PutClusterApiRegistration(&reg); err != nil {
		t.Fatalf("PutClusterApiRegistration (bump sync_id, canary): %v", err)
	}
	var wg sync.WaitGroup
	w.handleApiRegistrationPut(context.Background(), &wg, mustMarshal(t, reg))
	wg.Wait()

	canarySub, err := repo.GetNamespaceSubscription("canary-ns", "vault")
	if err != nil {
		t.Fatalf("GetNamespaceSubscription(canary-ns): %v", err)
	}
	if canarySub.CurrentSyncID != "sync-2" {
		t.Fatalf("canary-ns.CurrentSyncID = %q, want sync-2 (canary namespace should reconcile)", canarySub.CurrentSyncID)
	}

	otherSub, err := repo.GetNamespaceSubscription("other-ns", "vault")
	if err != nil {
		t.Fatalf("GetNamespaceSubscription(other-ns): %v", err)
	}
	if otherSub.CurrentSyncID != "sync-1" {
		t.Fatalf("other-ns.CurrentSyncID = %q, want still sync-1 (left pending, not canaried)", otherSub.CurrentSyncID)
	}

	// release: same SyncID, no restriction — other-ns now reconciles too.
	reg.CanaryNamespaces = nil
	if err := repo.PutClusterApiRegistration(&reg); err != nil {
		t.Fatalf("PutClusterApiRegistration (release): %v", err)
	}
	w.handleApiRegistrationPut(context.Background(), &wg, mustMarshal(t, reg))
	wg.Wait()

	otherSub, err = repo.GetNamespaceSubscription("other-ns", "vault")
	if err != nil {
		t.Fatalf("GetNamespaceSubscription(other-ns) after release: %v", err)
	}
	if otherSub.CurrentSyncID != "sync-2" {
		t.Fatalf("other-ns.CurrentSyncID after release = %q, want sync-2", otherSub.CurrentSyncID)
	}
}

// TestReconcileErrorsOnlyWhenModeIsEmpty confirms mode is a free-form key
// into reconciler.mode, not a fixed enum: reconcile only ever fails for
// having no mode at all (no ApiRegistration.Mode and no reconciler.default_mode).
// Any non-empty name succeeds — here via the log-only placeholder, since
// none of them have steps configured.
func TestReconcileErrorsOnlyWhenModeIsEmpty(t *testing.T) {
	repo := newTestRepo(t)
	w := NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL})

	if err := w.reconcile(ApiRegistration{Name: "vault", Mode: ""}, "myns", Subscription{}, 0); err == nil {
		t.Fatal("reconcile with empty mode and no default_mode: want error, got nil")
	}
	for _, mode := range []string{"trigger", "api", "anything-else"} {
		if err := w.reconcile(ApiRegistration{Name: "vault", Mode: mode}, "myns", Subscription{}, 0); err != nil {
			t.Fatalf("reconcile with mode %q: want nil error, got %v", mode, err)
		}
	}
}

// TestReconcileFallsBackToDefaultMode confirms a Reconciler configured
// with defaultMode runs that mode's steps for a reg with no Mode of its
// own, and that an explicit ApiRegistration.Mode is never overridden by it — each
// mode here has its own steps hitting a different server, so which one
// actually ran is directly observable.
func TestReconcileFallsBackToDefaultMode(t *testing.T) {
	var triggerCalled, apiCalled atomic.Bool
	triggerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		triggerCalled.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer triggerSrv.Close()
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalled.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer apiSrv.Close()

	repo := newTestRepo(t)
	w := NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL,
		DefaultMode: "trigger",
		Mode: map[string][]config.ReconcileStep{
			"trigger": {{Method: "get", Endpoint: triggerSrv.URL, Timeout: "5s"}},
			"api":     {{Method: "get", Endpoint: apiSrv.URL, Timeout: "5s"}},
		},
	})

	// Mode unset: falls back to default_mode ("trigger").
	if err := w.reconcile(ApiRegistration{Name: "vault", Mode: ""}, "myns", Subscription{}, 0); err != nil {
		t.Fatalf("reconcile with Mode unset: %v", err)
	}
	if !triggerCalled.Load() || apiCalled.Load() {
		t.Fatalf("Mode unset: triggerCalled=%v apiCalled=%v, want only trigger (the default)", triggerCalled.Load(), apiCalled.Load())
	}

	triggerCalled.Store(false)
	apiCalled.Store(false)

	// Explicit Mode: "api" wins over default_mode's "trigger".
	if err := w.reconcile(ApiRegistration{Name: "vault", Mode: "api"}, "myns", Subscription{}, 0); err != nil {
		t.Fatalf("reconcile with Mode=api: %v", err)
	}
	if !apiCalled.Load() || triggerCalled.Load() {
		t.Fatalf("Mode=api: triggerCalled=%v apiCalled=%v, want only api (explicit mode wins)", triggerCalled.Load(), apiCalled.Load())
	}
}

// TestReconcilerDefaultModeActivatesModeLessApiRegistration confirms a subscription
// to a reg with no Mode of its own still activates, end to end, when
// the Reconciler itself is configured with a default_mode.
func TestReconcilerDefaultModeActivatesModeLessApiRegistration(t *testing.T) {
	repo := newTestRepo(t)

	if err := repo.PutClusterApiRegistration(&ApiRegistration{
		Name: "vault", Platform: testDeployPlatform, Region: testDeployRegion, Active: true,
		SyncID: "sync-1", // Mode deliberately left unset.
	}); err != nil {
		t.Fatalf("PutClusterApiRegistration: %v", err)
	}
	if err := repo.PutNamespaceSubscription("myns", &Subscription{ApiName: "vault", State: SubscriptionStateInit}); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL, MaxConcurrentReconciles: 0, DefaultMode: "api"}).Run(ctx)
	}()

	waitFor(t, func() bool {
		sub, err := repo.GetNamespaceSubscription("myns", "vault")
		return err == nil && sub.Active && sub.CurrentSyncID == "sync-1"
	}, "subscription myns/vault to activate via the reconciler's default_mode")
}

// TestReconcilerReconcileFailureLeavesSubscriptionUnsynced confirms a
// subscription whose reg has no usable mode stays exactly as unsynced
// as it started — CurrentSyncID is never advanced ahead of reconcile
// actually succeeding — and that it's retried from scratch (nothing ever
// marked it "done" in the meantime) once the reg's mode is fixed and
// something re-evaluates the subscription: here, a fresh Reconciler's
// startup reconcile pass, which — unlike a live watch, especially
// LocalStore's poll-and-diff one — lists every record directly rather
// than needing a change to react to.
func TestReconcilerReconcileFailureLeavesSubscriptionUnsynced(t *testing.T) {
	repo := newTestRepo(t)

	if err := repo.PutClusterApiRegistration(&ApiRegistration{
		Name: "vault", Platform: testDeployPlatform, Region: testDeployRegion, Active: true,
		SyncID: "sync-1", // Mode deliberately left unset: reconcile can never succeed.
	}); err != nil {
		t.Fatalf("PutClusterApiRegistration: %v", err)
	}
	if err := repo.PutNamespaceSubscription("myns", &Subscription{ApiName: "vault", State: SubscriptionStateInit}); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}

	ctx1, cancel1 := context.WithCancel(context.Background())
	go func() {
		_ = NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL, MaxConcurrentReconciles: 0, DefaultMode: ""}).Run(ctx1)
	}()

	time.Sleep(300 * time.Millisecond)
	cancel1()

	got, err := repo.GetNamespaceSubscription("myns", "vault")
	if err != nil {
		t.Fatalf("GetNamespaceSubscription: %v", err)
	}
	if got.Active || got.CurrentSyncID != "" {
		t.Fatalf("sub = %+v, want still inactive with empty CurrentSyncID (reconcile never succeeds)", got)
	}
	if got.State != SubscriptionStateError {
		t.Fatalf("sub.State = %q, want %q after a failed sync", got.State, SubscriptionStateError)
	}
	// Marking the failure must not keep re-triggering the Reconciler:
	// once State is error, a further failure writes nothing.
	settled := got.UpdatedAt
	time.Sleep(300 * time.Millisecond)
	if again, err := repo.GetNamespaceSubscription("myns", "vault"); err != nil || !again.UpdatedAt.Equal(settled) {
		t.Fatalf("subscription kept being rewritten after the failure (updated_at %v -> %v, err %v): reconcile/mark-error loop", settled, again.UpdatedAt, err)
	}

	if err := repo.PutClusterApiRegistration(&ApiRegistration{
		Name: "vault", Platform: testDeployPlatform, Region: testDeployRegion, Active: true,
		SyncID: "sync-1", Mode: "trigger",
	}); err != nil {
		t.Fatalf("PutClusterApiRegistration (fix mode): %v", err)
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() {
		_ = NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL, MaxConcurrentReconciles: 0, DefaultMode: ""}).Run(ctx2)
	}()

	waitFor(t, func() bool {
		got, err := repo.GetNamespaceSubscription("myns", "vault")
		return err == nil && got.Active && got.CurrentSyncID == "sync-1" && got.State == SubscriptionStateSuccess
	}, "subscription myns/vault to activate (state success) once the reg's mode is fixed")
}

func TestNewReconcilerDefaultsMaxConcurrentReconciles(t *testing.T) {
	repo := newTestRepo(t)

	for _, n := range []int{0, -1, -100} {
		w := NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL, MaxConcurrentReconciles: n, DefaultMode: ""})
		if cap(w.sem) != DefaultMaxConcurrentReconciles {
			t.Fatalf("NewReconciler(..., %d): pool size = %d, want default %d", n, cap(w.sem), DefaultMaxConcurrentReconciles)
		}
	}

	w := NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL, MaxConcurrentReconciles: 5, DefaultMode: ""})
	if cap(w.sem) != 5 {
		t.Fatalf("NewReconciler(..., 5): pool size = %d, want 5", cap(w.sem))
	}
}

// TestReconcilerDispatchBoundsConcurrency confirms dispatch never runs
// more than the configured pool size at once, even when far more jobs are
// submitted than that — the mechanism handleNewNamespace,
// handleNewSubscription and handleApiRegistrationPut's reconcile loop all share.
func TestReconcilerDispatchBoundsConcurrency(t *testing.T) {
	repo := newTestRepo(t)
	const poolSize = 3
	w := NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL, MaxConcurrentReconciles: poolSize, DefaultMode: ""})

	const jobs = 10
	var (
		mu      sync.Mutex
		current int
		maxSeen int
		wg      sync.WaitGroup
	)

	release := make(chan struct{})
	go func() {
		time.Sleep(100 * time.Millisecond)
		close(release)
	}()

	for i := 0; i < jobs; i++ {
		w.dispatch(&wg, func(lockID int) {
			mu.Lock()
			current++
			if current > maxSeen {
				maxSeen = current
			}
			mu.Unlock()

			<-release

			mu.Lock()
			current--
			mu.Unlock()
		})
	}
	wg.Wait()

	if maxSeen > poolSize {
		t.Fatalf("maxSeen = %d, want <= %d (pool size)", maxSeen, poolSize)
	}
	if maxSeen != poolSize {
		t.Fatalf("maxSeen = %d, want exactly %d (pool should saturate with %d jobs)", maxSeen, poolSize, jobs)
	}
}

// TestReconcilerDispatchPoolIsPerProcess confirms dispatch's bound is
// purely local to one Reconciler: two independent instances each get
// their own full max_concurrent_reconciles allowance rather than sharing
// one — so fleet throughput scales with how many kayra reconciler
// processes run, each contributing its own pool, not a single ceiling
// split between them.
func TestReconcilerDispatchPoolIsPerProcess(t *testing.T) {
	const poolSize = 3
	wA := NewReconciler(newTestRepo(t), testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL, MaxConcurrentReconciles: poolSize})
	wB := NewReconciler(newTestRepo(t), testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL, MaxConcurrentReconciles: poolSize})

	const jobsPerReconciler = 10
	var (
		mu      sync.Mutex
		current int
		maxSeen int
		wg      sync.WaitGroup
	)

	release := make(chan struct{})
	go func() {
		time.Sleep(150 * time.Millisecond)
		close(release)
	}()

	track := func(lockID int) {
		mu.Lock()
		current++
		if current > maxSeen {
			maxSeen = current
		}
		mu.Unlock()

		<-release

		mu.Lock()
		current--
		mu.Unlock()
	}

	for i := 0; i < jobsPerReconciler; i++ {
		wA.dispatch(&wg, track)
		wB.dispatch(&wg, track)
	}
	wg.Wait()

	want := 2 * poolSize
	if maxSeen != want {
		t.Fatalf("maxSeen = %d, want exactly %d (each reconciler's own full pool, summed)", maxSeen, want)
	}
}

// fakeJobLockerStore wraps a store.Store with an in-memory
// store.JobLocker: one exclusive holder per key, shared by every holder
// of the same *fakeJobLockerStore pointer, exactly like EtcdStore's
// etcd-backed mutexes are shared by every kayra reconciler process
// pointed at the same cluster — standing in for a real etcd cluster so
// cross-process job exclusivity can be proven without one.
type fakeJobLockerStore struct {
	store.Store
	mu   sync.Mutex
	held map[string]bool
}

func newFakeJobLockerStore(s store.Store) *fakeJobLockerStore {
	return &fakeJobLockerStore{Store: s, held: map[string]bool{}}
}

func (f *fakeJobLockerStore) TryLock(ctx context.Context, key string) (bool, func() error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.held[key] {
		return false, nil, nil
	}
	f.held[key] = true
	return true, func() error {
		f.mu.Lock()
		delete(f.held, key)
		f.mu.Unlock()
		return nil
	}, nil
}

// withShortJobLockRetryInterval shortens jobLockRetryInterval for the
// duration of a test, so a contended distributed lock test doesn't
// actually wait out the real 100ms default per retry.
func withShortJobLockRetryInterval(t *testing.T) {
	t.Helper()
	orig := jobLockRetryInterval
	jobLockRetryInterval = 2 * time.Millisecond
	t.Cleanup(func() { jobLockRetryInterval = orig })
}

// TestReconcilerWithJobLockSerializesAcrossReconcilers confirms two
// independent *Reconciler instances sharing a JobLocker-capable store
// never both run the same job (same lock key) at once — the actual
// problem the distributed lock exists to solve: every reconciler process
// observes the identical watch event stream (etcd's Watch is a
// broadcast, not a work queue), so without this, both would redundantly
// react to the same event at the same time. Unlike a plain
// mutual-exclusion check, both still eventually run: the loser blocks and
// retries until the winner releases, rather than being skipped and left
// to some future event that might never come.
func TestReconcilerWithJobLockSerializesAcrossReconcilers(t *testing.T) {
	withShortJobLockRetryInterval(t)

	local, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	t.Cleanup(func() { _ = local.Close() })
	shared := newFakeJobLockerStore(local)

	wA := NewReconciler(NewRepository(shared, store.NewKeys("")), testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL})
	wB := NewReconciler(NewRepository(shared, store.NewKeys("")), testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL})

	const key = "namespaces/myns/subscriptions/vault"
	var (
		mu       sync.Mutex
		running  int
		maxSeen  int
		ranCount int32
		wg       sync.WaitGroup
		ready    = make(chan struct{})
	)

	run := func(r *Reconciler) {
		defer wg.Done()
		<-ready
		r.withJobLock(context.Background(), key, 0, func() {
			atomic.AddInt32(&ranCount, 1)
			mu.Lock()
			running++
			if running > maxSeen {
				maxSeen = running
			}
			mu.Unlock()

			time.Sleep(50 * time.Millisecond)

			mu.Lock()
			running--
			mu.Unlock()
		})
	}

	wg.Add(2)
	go run(wA)
	go run(wB)
	close(ready)
	wg.Wait()

	if maxSeen > 1 {
		t.Fatalf("maxSeen = %d, want <= 1 (only one reconciler should ever hold the same job's lock at once)", maxSeen)
	}
	if ranCount != 2 {
		t.Fatalf("ranCount = %d, want exactly 2 (both should eventually run, serialized, not one dropped)", ranCount)
	}
}

// TestReconcilerWithJobLockSerializesWithinOneProcess confirms the local
// (in-process) layer of withJobLock alone — with no store.JobLocker
// involved at all — still serializes two goroutines racing for the same
// key: the gap a LocalStore-backed deployment (or any single process)
// would otherwise have, since store.JobLocker only ever exists for
// EtcdStore.
func TestReconcilerWithJobLockSerializesWithinOneProcess(t *testing.T) {
	w := NewReconciler(newTestRepo(t), testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL})

	const key = "namespaces/myns/subscriptions/vault"
	var (
		mu       sync.Mutex
		running  int
		maxSeen  int
		ranCount int32
		wg       sync.WaitGroup
		ready    = make(chan struct{})
	)

	run := func() {
		defer wg.Done()
		<-ready
		w.withJobLock(context.Background(), key, 0, func() {
			atomic.AddInt32(&ranCount, 1)
			mu.Lock()
			running++
			if running > maxSeen {
				maxSeen = running
			}
			mu.Unlock()

			time.Sleep(50 * time.Millisecond)

			mu.Lock()
			running--
			mu.Unlock()
		})
	}

	wg.Add(2)
	go run()
	go run()
	close(ready)
	wg.Wait()

	if maxSeen > 1 {
		t.Fatalf("maxSeen = %d, want <= 1 (same key must never run twice at once within one process)", maxSeen)
	}
	if ranCount != 2 {
		t.Fatalf("ranCount = %d, want exactly 2 (both should eventually run, serialized)", ranCount)
	}
}

// TestEnsureReconciledCoalescesRacingCallsForSameSubscription confirms
// the actual payoff of withJobLock plus ensureReconciled's
// re-read-after-lock: two calls racing for the same namespace/api registration —
// e.g. handleApiRegistrationPut's fan-out and handleNewSubscription dispatching for
// the same pair at nearly the same moment — never both run reconcile. The
// loser blocks on the lock, and once it gets its turn, sees (from a fresh
// read, not the stale snapshot it was dispatched with) that the winner
// already reconciled the subscription, so it no-ops instead of
// redundantly firing the HTTP step pipeline a second time.
func TestEnsureReconciledCoalescesRacingCallsForSameSubscription(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	repo := newTestRepo(t)
	if err := repo.PutClusterApiRegistration(&ApiRegistration{
		Name: "vault", Platform: testDeployPlatform, Region: testDeployRegion,
		Active: true, SyncID: "sync-1", Mode: "trigger",
	}); err != nil {
		t.Fatalf("PutClusterApiRegistration: %v", err)
	}
	if err := repo.PutNamespaceSubscription("myns", &Subscription{ApiName: "vault", State: SubscriptionStateInit}); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}

	w := NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{GatewayURL: testGatewayURL,
		Mode: map[string][]config.ReconcileStep{
			"trigger": {{Method: "post", Endpoint: srv.URL, Timeout: "5s"}},
		},
	})

	reg, err := repo.GetClusterApiRegistration(testDeployPlatform, testDeployRegion, "vault")
	if err != nil {
		t.Fatalf("GetClusterApiRegistration: %v", err)
	}
	sub, err := repo.GetNamespaceSubscription("myns", "vault")
	if err != nil {
		t.Fatalf("GetNamespaceSubscription: %v", err)
	}

	var wg sync.WaitGroup
	ready := make(chan struct{})
	run := func() {
		defer wg.Done()
		<-ready
		w.ensureReconciled(context.Background(), reg, "myns", sub, 0)
	}
	wg.Add(2)
	go run()
	go run()
	close(ready)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("HTTP calls = %d, want exactly 1 (the second racing call must see it's already reconciled and no-op)", got)
	}

	final, err := repo.GetNamespaceSubscription("myns", "vault")
	if err != nil {
		t.Fatalf("GetNamespaceSubscription: %v", err)
	}
	if !final.Active || final.CurrentSyncID != "sync-1" {
		t.Fatalf("final sub = %+v, want active/sync-1", final)
	}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
