package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/infrapi/kayra/internal/config"
	"github.com/infrapi/kayra/internal/store"
)

// DefaultMaxConcurrentReconciles is the goroutine pool size NewReconciler
// falls back to when maxConcurrentReconciles is <= 0.
const DefaultMaxConcurrentReconciles = 30

// localJobLockPollInterval is how often keyedLock re-checks whether a
// contended key has freed up. A var, not a const, so tests can shorten
// it rather than waiting out a real interval.
var localJobLockPollInterval = 10 * time.Millisecond

// jobLockRetryInterval is how often withJobLock re-attempts a contended
// distributed lock (store.JobLocker.TryLock only ever makes one
// non-blocking attempt itself) while waiting for whichever other kayra
// reconciler process currently holds it to release it. A var, not a const,
// so tests can shorten it.
var jobLockRetryInterval = 100 * time.Millisecond

// keyedLock is a purely in-process mutex-per-key: it guarantees two
// goroutines in this one process never hold the same key at once,
// regardless of which store backend is active. store.JobLocker only
// exists for EtcdStore, so without this, two reconciles racing for the
// same namespace/api registration within a single LocalStore-backed
// process (handleApiRegistrationPut's fan-out and handleNewSubscription
// can both dispatch one for the same pair at nearly the same moment)
// would run fully concurrently with nothing serializing them.
type keyedLock struct {
	mu   sync.Mutex
	held map[string]bool
}

func newKeyedLock() *keyedLock {
	return &keyedLock{held: map[string]bool{}}
}

// lock blocks until key is free, then holds it and returns a release
// func — or returns ctx's error if ctx is canceled first. Polls rather
// than using a condition variable purely so ctx cancellation is trivial;
// a key is held for however long one reconcile takes (seconds, not
// sub-millisecond), so polling costs nothing of consequence here.
func (k *keyedLock) lock(ctx context.Context, key string) (func(), error) {
	for {
		k.mu.Lock()
		if !k.held[key] {
			k.held[key] = true
			k.mu.Unlock()
			return func() {
				k.mu.Lock()
				delete(k.held, key)
				k.mu.Unlock()
			}, nil
		}
		k.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(localJobLockPollInterval):
		}
	}
}

// Reconciler turns the Store's Watch (etcd's native MVCC watch, or
// LocalStore's polling fallback — see internal/store.Store.Watch) into the
// event-driven trigger that:
//
//   - moves a namespace or subscription out of the disabled/init state the
//     public API always creates it in (see RegisterNamespaceCollectionRoutes
//     and RegisterNamespaceRoutes' "/subscriptions" routes) — the "initial
//     action";
//   - reconciles every already-active subscription against an api
//     registration whenever its own SyncID moves on — the "ongoing"
//     action, triggered by a plain admin PUT to the registration
//     (bumping ApiRegistration.SyncID is the entire trigger, there is
//     no separate "/reconcile" endpoint).
//
// Repository.ActivateNamespace/ActivateSubscription/SetSubscriptionSyncID
// are all idempotent, so re-observing an already-reconciled record
// (including the Reconciler's own write) is a no-op.
type Reconciler struct {
	repo                                 *Repository
	deploymentPlatform, deploymentRegion string
	// sem bounds how many of the goroutines dispatch spawns run at once,
	// purely within this process — every namespace/subscription
	// activation and every registration-triggered subscription reconcile
	// shares this one pool, sized by maxConcurrentReconciles (see
	// NewReconciler) and prefilled with every slot index
	// 0..maxConcurrentReconciles-1. An api registration whose SyncID
	// changes can fan out into reconciling hundreds of subscriptions at
	// once; without this, nothing would cap how many of those run
	// concurrently. Receiving from it both claims a slot and names it
	// (the lock_id every reconcile-path log line carries, so concurrent
	// activity within one process's logs can be told apart); sending a
	// slot back releases it. This bound is not shared across processes:
	// running several kayra reconciler instances against the same store
	// multiplies total fleet throughput by however many there are, each
	// with its own independent pool — see withJobLock for the actual
	// cross-process coordination, which solves a different problem.
	sem chan int
	// jobLocks is the in-process layer of withJobLock's mutual exclusion
	// — see keyedLock — always active regardless of store backend.
	jobLocks *keyedLock
	// defaultMode is what reconcile falls back to when an api
	// registration's own Mode is unset (config.ReconcilerConfig.DefaultMode)
	// — empty keeps reconcile failing for such a registration, exactly as
	// if no default were configured at all. A registration's own Mode,
	// when it has one, always wins over this.
	defaultMode string
	// modeSteps is config.ReconcilerConfig.Mode: the HTTP step pipeline to
	// run for a given (post-DefaultMode-fallback) mode name. A mode with
	// no entry here keeps reconcile's placeholder log-only behavior.
	modeSteps map[string][]config.ReconcileStep
}

// NewReconciler returns a Reconciler over repo's store. deploymentPlatform/
// deploymentRegion are this instance's own INFRAPI_APP_PLATFORM/_REGION —
// needed because a Subscription carries no platform/region of its own (see
// Subscription): it can only ever mean the api registration of that name in
// this deployment's own platform/region. cfg is the kayra.yaml reconciler:
// block as-is — MaxConcurrentReconciles <= 0 falls back to
// DefaultMaxConcurrentReconciles, DefaultMode and Mode are described on
// Reconciler.defaultMode/modeSteps.
func NewReconciler(repo *Repository, deploymentPlatform, deploymentRegion string, cfg config.ReconcilerConfig) *Reconciler {
	maxConcurrentReconciles := cfg.MaxConcurrentReconciles
	if maxConcurrentReconciles <= 0 {
		maxConcurrentReconciles = DefaultMaxConcurrentReconciles
	}
	sem := make(chan int, maxConcurrentReconciles)
	for i := 0; i < maxConcurrentReconciles; i++ {
		sem <- i
	}
	return &Reconciler{
		repo:               repo,
		deploymentPlatform: deploymentPlatform,
		deploymentRegion:   deploymentRegion,
		sem:                sem,
		jobLocks:           newKeyedLock(),
		defaultMode:        cfg.DefaultMode,
		modeSteps:          cfg.Mode,
	}
}

// dispatch runs fn in its own goroutine once a slot in r.sem is free,
// blocking the caller until then — the process-local bounded-concurrency
// gate every reconcile/activate operation goes through. wg lets Run (and
// reconcileExisting) wait for every goroutine it started before returning.
// fn receives that slot's lock_id — the one identifier every log line
// along the reconcile path carries, so concurrent activity within this
// process's own logs can be told apart. This bound is purely local to this
// process; see withJobLock for the cross-process coordination a fn body
// typically layers on top of it.
func (r *Reconciler) dispatch(wg *sync.WaitGroup, fn func(lockID int)) {
	wg.Add(1)
	lockID := <-r.sem
	go func() {
		defer wg.Done()
		defer func() { r.sem <- lockID }()
		fn(lockID)
	}()
}

// withJobLock runs run() only once it holds exclusive ownership of key —
// both within this process (r.jobLocks, always enforced, regardless of
// store backend) and, when the store also implements store.JobLocker,
// across every other kayra reconciler process sharing it too. Either
// layer blocks until it can acquire key rather than giving up: two
// reconciles racing for the same namespace/api registration are
// serialized, never run concurrently, but the later one still runs once
// its turn comes — it isn't silently skipped and left to some future
// event to retry, which might never arrive (e.g. a force-sync PUT that's
// itself the only reason to re-reconcile at all, racing an already
// in-flight run for the same subscription, would otherwise be dropped
// on the floor).
//
// This exists because of two distinct races: within one process, an api
// registration's own SyncID bump (handleApiRegistrationPut's fan-out)
// and that same subscription's own record being touched
// (handleNewSubscription) can both dispatch an ensureReconciled call for
// the same namespace/api pair at once — r.jobLocks alone closes this,
// regardless of backend. Across processes, every reconciler process
// observes the identical watch event stream (etcd's Watch is a
// broadcast, not a work queue), so without the distributed layer, every
// one of them would otherwise redundantly run the same job at the same
// time too — this is the layer LocalStore (a single dev process,
// nothing else to coordinate with) doesn't need and doesn't implement.
//
// Callers that pass stale data captured before the wait (see
// ensureReconciled/handleNewNamespace) must re-check it fresh once run()
// actually starts: whichever call wins the lock may already have done
// the work the loser was about to redundantly repeat.
func (r *Reconciler) withJobLock(ctx context.Context, key string, lockID int, run func()) {
	releaseLocal, err := r.jobLocks.lock(ctx, key)
	if err != nil {
		log.Printf("catalog: reconciler: lock_id=%d wait for local lock %s: %v", lockID, key, err)
		return
	}
	defer releaseLocal()

	if locker, ok := r.repo.store.(store.JobLocker); ok {
		release, err := waitForJobLock(ctx, locker, key)
		if err != nil {
			log.Printf("catalog: reconciler: lock_id=%d wait for distributed lock %s: %v", lockID, key, err)
			return
		}
		defer func() {
			if err := release(); err != nil {
				log.Printf("catalog: reconciler: lock_id=%d release %s: %v", lockID, key, err)
			}
		}()
	}

	run()
}

// waitForJobLock turns locker.TryLock's single non-blocking attempt into
// "wait until free": it retries every jobLockRetryInterval until TryLock
// reports ok, or ctx is canceled.
func waitForJobLock(ctx context.Context, locker store.JobLocker, key string) (func() error, error) {
	for {
		ok, release, err := locker.TryLock(ctx, key)
		if err != nil {
			return nil, err
		}
		if ok {
			return release, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(jobLockRetryInterval):
		}
	}
}

// Run reconciles every existing disabled namespace/subscription, then
// watches both the namespaces tree and the cluster api registrations
// tree until ctx is canceled. It blocks until ctx is done or both
// underlying Watches end, so callers run it in its own goroutine. Every
// dispatched goroutine is awaited before Run returns, so no
// reconcile/activate call is still running — and possibly still
// touching the store — after it does.
func (r *Reconciler) Run(ctx context.Context) error {
	if err := r.reconcileExisting(ctx); err != nil {
		log.Printf("catalog: reconciler: initial reconcile: %v", err)
	}

	nsEvents, err := r.repo.store.Watch(ctx, r.repo.keys.NamespacesPrefix())
	if err != nil {
		return fmt.Errorf("catalog: watch namespaces: %w", err)
	}
	apiEvents, err := r.repo.store.Watch(ctx, r.repo.keys.ClusterApiRegistrationPrefix())
	if err != nil {
		return fmt.Errorf("catalog: watch cluster api registrations: %w", err)
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	for nsEvents != nil || apiEvents != nil {
		select {
		case ev, ok := <-nsEvents:
			if !ok {
				nsEvents = nil
				continue
			}
			if ev.Type == store.EventTypePut {
				r.handleNamespacesPut(ctx, &wg, ev.Key, ev.Value)
			}
		case ev, ok := <-apiEvents:
			if !ok {
				apiEvents = nil
				continue
			}
			if ev.Type == store.EventTypePut {
				r.handleApiRegistrationPut(ctx, &wg, ev.Value)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return ctx.Err()
}

// reconcileExisting activates every namespace/subscription that's already
// disabled/init before Watch ever starts. Without this, a record written
// before the Reconciler starts (or while it wasn't running) would never be
// seen: Watch, like etcd's own MVCC watch, only streams changes from here
// forward — never a snapshot of what already exists.
func (r *Reconciler) reconcileExisting(ctx context.Context) error {
	entries, err := r.repo.store.List(r.repo.keys.NamespacesPrefix())
	if err != nil {
		return fmt.Errorf("catalog: list namespaces: %w", err)
	}

	var wg sync.WaitGroup
	for key, value := range entries {
		r.handleNamespacesPut(ctx, &wg, key, value)
	}
	wg.Wait()
	return nil
}

// handleNamespacesPut decides what, if anything, key/value is (a
// namespace's own config record, or one of its subscriptions' —
// everything else nested under the namespaces tree, e.g. rbac's
// groups/roles/rolebindings, is ignored) and dispatches the "initial
// action" on it if it's still new.
func (r *Reconciler) handleNamespacesPut(ctx context.Context, wg *sync.WaitGroup, key string, value []byte) {
	rest := strings.TrimPrefix(key, r.repo.keys.NamespacesPrefix())
	segments := strings.Split(rest, "/")

	switch {
	case len(segments) == 2 && segments[1] == "config":
		name := segments[0]
		r.dispatch(wg, func(lockID int) { r.handleNewNamespace(ctx, name, value, lockID) })
	case len(segments) == 4 && segments[1] == "subscriptions" && segments[3] == "config":
		namespace, apiName := segments[0], segments[2]
		r.dispatch(wg, func(lockID int) { r.handleNewSubscription(ctx, namespace, apiName, value, lockID) })
	}
}

func (r *Reconciler) handleNewNamespace(ctx context.Context, name string, value []byte, lockID int) {
	var n Namespace
	if err := json.Unmarshal(value, &n); err != nil {
		log.Printf("catalog: reconciler: lock_id=%d decode namespace %q: %v", lockID, name, err)
		return
	}
	if n.Active {
		return
	}

	r.withJobLock(ctx, r.repo.keys.ReconcilerNamespaceLock(name), lockID, func() {
		// Re-read fresh now that the lock is held: a racing call that
		// got here first may have already activated it, in which case
		// this one has nothing left to do.
		if fresh, err := r.repo.GetNamespace(name); err == nil && fresh.Active {
			return
		}

		if err := r.repo.ActivateNamespace(name); err != nil {
			log.Printf("catalog: reconciler: lock_id=%d activate namespace %q: %v", lockID, name, err)
			return
		}
		log.Printf("catalog: reconciler: lock_id=%d activated namespace %q", lockID, name)
	})
}

// handleNewSubscription is the "initial action": it looks up the api
// registration a just-written subscription names and hands both to
// ensureReconciled, which decides whether anything actually needs to
// happen — a subscription that's already active and reconciled
// (including the Reconciler's own write echoing back through this same
// watch) is a no-op.
func (r *Reconciler) handleNewSubscription(ctx context.Context, namespace, apiName string, value []byte, lockID int) {
	var sub Subscription
	if err := json.Unmarshal(value, &sub); err != nil {
		log.Printf("catalog: reconciler: lock_id=%d decode subscription %s/%s: %v", lockID, namespace, apiName, err)
		return
	}

	reg, err := r.repo.GetClusterApiRegistration(r.deploymentPlatform, r.deploymentRegion, apiName)
	if err != nil {
		log.Printf("catalog: reconciler: lock_id=%d lookup api registration %q for subscription %s: %v", lockID, apiName, namespace, err)
		return
	}

	r.ensureReconciled(ctx, reg, namespace, sub, lockID)
}

// handleApiRegistrationPut is the "ongoing" action: whenever an api
// registration's own record changes, every namespace already actively
// subscribed to it, whose own CurrentSyncID doesn't match the
// registration's current one, is handed to ensureReconciled — each
// dispatched through the same bounded pool as every other reconcile
// operation, so a registration with many subscribers can't fan out into
// unbounded concurrency. A subscription that isn't active yet is skipped
// here; it's already handled by handleNewSubscription the moment it's
// created (or retried, see ensureReconciled, the next time its own
// record is touched), so reconciling it again here would just be
// redundant dispatch overhead for a no-op.
//
// A non-empty reg.CanaryNamespaces (see ApiRegistration and PUT
// .../sync) restricts this fan-out to just those namespaces: every
// other active, unreconciled subscriber is left exactly as it was,
// pending — until a later write clears CanaryNamespaces (a release
// sync), at which point this same fan-out runs again for all of them.
func (r *Reconciler) handleApiRegistrationPut(ctx context.Context, wg *sync.WaitGroup, value []byte) {
	var reg ApiRegistration
	if err := json.Unmarshal(value, &reg); err != nil {
		log.Printf("catalog: reconciler: decode api registration: %v", err)
		return
	}
	if reg.Platform != r.deploymentPlatform || reg.Region != r.deploymentRegion {
		return
	}

	subs, err := r.repo.ListSubscriptionsToApi(reg.Name)
	if err != nil {
		log.Printf("catalog: reconciler: list subscriptions to api %q: %v", reg.Name, err)
		return
	}

	for namespace, sub := range subs {
		if !sub.Active || sub.CurrentSyncID == reg.SyncID {
			continue
		}
		if len(reg.CanaryNamespaces) > 0 && !containsString(reg.CanaryNamespaces, namespace) {
			continue
		}
		r.dispatch(wg, func(lockID int) { r.ensureReconciled(ctx, reg, namespace, sub, lockID) })
	}
}

// ensureReconciled is the one decision every reconcile path shares: sub
// needs reconciling against reg whenever it isn't both active and
// already at reg's current SyncID — covering a brand-new subscription
// (Active: false, CurrentSyncID: "", which can never equal a
// registration's SyncID by coincidence alone unless that too is still
// unset, in which case Active being false still catches it) exactly the
// same way it covers an active one whose registration has since moved
// on.
//
// CurrentSyncID only ever advances once reconcile itself reports success
// — never optimistically ahead of it. A failed reconcile (today: only an
// unconfigured/unrecognized ApiRegistration.Mode — see reconcile) leaves
// CurrentSyncID exactly where it was: absent for a subscription that's
// never been activated, stale for one that has. Either way the next
// write to this subscription's own record, or to its api registration,
// re-evaluates it from scratch and retries — nothing here ever marks a
// subscription "done" independently of reconcile actually succeeding.
func (r *Reconciler) ensureReconciled(ctx context.Context, reg ApiRegistration, namespace string, sub Subscription, lockID int) {
	if sub.Active && sub.CurrentSyncID == reg.SyncID {
		return
	}
	// A registration with no SyncID at all has nothing yet to reconcile
	// any subscriber to — reconcile only ever runs to catch a
	// subscription up to a specific SyncID, and there is none here.
	// Without this, a brand-new subscription (Active: false,
	// CurrentSyncID: "") would pass the check above against an equally
	// -empty reg.SyncID and reconcile immediately, running the
	// registration's real provisioning action before its owner ever
	// bumped SyncID even once. Left pending here, it's picked up the
	// moment the registration's own SyncID does move
	// (handleApiRegistrationPut) or its own record is next touched.
	if reg.SyncID == "" {
		return
	}

	r.withJobLock(ctx, r.repo.keys.ReconcilerSubscriptionLock(namespace, reg.Name), lockID, func() {
		// Re-read both fresh now that the lock is held: a racing call
		// that got here first (and already finished) may have changed
		// what's true out from under the snapshot this call was
		// dispatched with, including to a newer SyncID than the one
		// this call still has in hand.
		if freshSub, err := r.repo.GetNamespaceSubscription(namespace, reg.Name); err == nil {
			sub = freshSub
		}
		if freshReg, err := r.repo.GetClusterApiRegistration(r.deploymentPlatform, r.deploymentRegion, reg.Name); err == nil {
			reg = freshReg
		}
		if sub.Active && sub.CurrentSyncID == reg.SyncID {
			return
		}
		if reg.SyncID == "" {
			return
		}

		if err := r.reconcile(reg, namespace, sub, lockID); err != nil {
			log.Printf("catalog: reconciler: lock_id=%d sync_id=%q reconcile %s/%s: %v", lockID, reg.SyncID, namespace, reg.Name, err)
			return
		}

		if !sub.Active {
			if err := r.repo.ActivateSubscription(namespace, reg.Name, reg.SyncID); err != nil {
				log.Printf("catalog: reconciler: lock_id=%d sync_id=%q activate subscription %s/%s: %v", lockID, reg.SyncID, namespace, reg.Name, err)
				return
			}
			log.Printf("catalog: reconciler: lock_id=%d sync_id=%q activated subscription %s/%s", lockID, reg.SyncID, namespace, reg.Name)
			return
		}

		if err := r.repo.SetSubscriptionSyncID(namespace, reg.Name, reg.SyncID); err != nil {
			log.Printf("catalog: reconciler: lock_id=%d sync_id=%q reconcile subscription %s/%s: %v", lockID, reg.SyncID, namespace, reg.Name, err)
			return
		}
		log.Printf("catalog: reconciler: lock_id=%d sync_id=%q reconciled subscription %s/%s", lockID, reg.SyncID, namespace, reg.Name)
	})
}

// reconcile carries out the real work an api registration's Mode drives
// — "trigger" (kick a CI pipeline) or "api" (call a provisioning API
// directly), or any other name a deployment's own reconciler.mode
// config uses. A registration with no Mode of its own falls back to
// Reconciler.defaultMode (config.ReconcilerConfig.DefaultMode) — set
// once for a deployment so a registration whose owner never bothered
// with mode: doesn't fail reconcile forever; an explicit
// ApiRegistration.Mode always wins over it. It errors when neither
// resolves to any mode at all: there is no way to carry out
// reconciliation without knowing which one it should be, so
// ensureReconciled must not advance CurrentSyncID as if it had.
//
// If the resolved mode has steps configured under reconciler.mode.<mode>,
// those run for real (see runSteps) and reconcile's result is theirs. If
// it doesn't — including every deployment that hasn't configured
// reconciler.mode at all yet — reconcile falls back to its original
// placeholder: log which mode would run and succeed unconditionally.
func (r *Reconciler) reconcile(reg ApiRegistration, namespace string, sub Subscription, lockID int) error {
	mode := reg.Mode
	if mode == "" {
		mode = r.defaultMode
	}
	if mode == "" {
		return fmt.Errorf("api registration %q has no mode set and no reconciler.default_mode is configured", reg.Name)
	}

	steps, ok := r.modeSteps[mode]
	if !ok || len(steps) == 0 {
		log.Printf("catalog: reconciler: lock_id=%d sync_id=%q reconcile %s/%s: mode=%s (no steps configured, placeholder)",
			lockID, reg.SyncID, namespace, reg.Name, mode)
		return nil
	}

	data := stepTemplateData{Subscription: subscriptionTemplateData{
		Api:            reg.Name,
		ShortName:      reg.ShortName,
		Namespace:      namespace,
		Platform:       r.deploymentPlatform,
		Region:         r.deploymentRegion,
		CurrentSyncID:  sub.CurrentSyncID,
		ExpectedSyncID: reg.SyncID,
	}}
	return runSteps(steps, data, lockID)
}
