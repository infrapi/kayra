package catalog

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/infrapi/kayra/internal/store"
)

// Repository persists the catalog's Stack/Namespace/Subscription records
// under the etcd/local key layout internal/store.Keys defines, sharing
// the same "/config" record convention internal/rbac uses (via
// internal/store's generic JSON helpers) so both packages' keys can
// coexist under the same namespace tree without colliding.
type Repository struct {
	store store.Store
	keys  store.Keys
}

// NewRepository returns a Repository backed by s, addressed through keys.
func NewRepository(s store.Store, keys store.Keys) *Repository {
	return &Repository{store: s, keys: keys}
}

// --- Cluster-scoped stacks ---

func (r *Repository) PutClusterStack(s Stack) error {
	return store.PutJSON(r.store, r.keys.ClusterStackConfig(s.Platform, s.Region, s.Name), s)
}

func (r *Repository) GetClusterStack(platform, region, name string) (Stack, error) {
	var s Stack
	err := store.GetJSON(r.store, r.keys.ClusterStackConfig(platform, region, name), &s)
	return s, err
}

func (r *Repository) ListClusterStacks() ([]Stack, error) {
	raw, err := store.ListConfigValues(r.store, r.keys.ClusterStackPrefix())
	if err != nil {
		return nil, err
	}
	stacks := make([]Stack, len(raw))
	for i, data := range raw {
		if err := json.Unmarshal(data, &stacks[i]); err != nil {
			return nil, fmt.Errorf("catalog: unmarshal cluster stack: %w", err)
		}
	}
	return stacks, nil
}

func (r *Repository) DeleteClusterStack(platform, region, name string) error {
	if err := r.store.Delete(r.keys.ClusterStackConfig(platform, region, name)); err != nil {
		return fmt.Errorf("catalog: delete cluster stack %s/%s/%s: %w", platform, region, name, err)
	}
	return nil
}

// stackIsReferenced reports whether any other Stack's DependsOn, or any
// namespace's Subscription, still points at the stack identified by
// platform/region/name — checked before allowing a delete. A Subscription
// carries no platform/region of its own (see Subscription), so it can
// only ever reference a stack in this deployment's own
// deploymentPlatform/deploymentRegion; subscriptions are skipped entirely
// when deleting a stack outside that scope, since none could reference it.
func (r *Repository) stackIsReferenced(platform, region, name, deploymentPlatform, deploymentRegion string) (bool, error) {
	stacks, err := r.ListClusterStacks()
	if err != nil {
		return false, err
	}
	ref := StackRef{Platform: platform, Region: region, Name: name}
	for _, s := range stacks {
		if s.Platform == platform && s.Region == region && s.Name == name {
			continue // a stack doesn't count as referencing itself
		}
		for _, dep := range s.DependsOn {
			if dep == ref {
				return true, nil
			}
		}
	}

	if platform != deploymentPlatform || region != deploymentRegion {
		return false, nil
	}

	entries, err := r.store.List(r.keys.NamespacesPrefix())
	if err != nil {
		return false, fmt.Errorf("catalog: scan namespaces for subscriptions: %w", err)
	}
	suffix := fmt.Sprintf("/subscriptions/%s/config", name)
	for key := range entries {
		if strings.HasSuffix(key, suffix) {
			return true, nil
		}
	}

	return false, nil
}

// --- Namespaces (the legacy model's "Tenant": a namespace is a tenant) ---

func (r *Repository) PutNamespace(n Namespace) error {
	return store.PutJSON(r.store, r.keys.NamespaceConfig(n.Name), n)
}

func (r *Repository) GetNamespace(name string) (Namespace, error) {
	var n Namespace
	err := store.GetJSON(r.store, r.keys.NamespaceConfig(name), &n)
	return n, err
}

// ActivateNamespace marks namespace active. The public API
// (RegisterNamespaceCollectionRoutes) never calls this — it always writes
// namespaces disabled — so this is the only path that can ever flip Active
// to true; only trusted in-process code (the Reconciler) should call it.
func (r *Repository) ActivateNamespace(name string) error {
	n, err := r.GetNamespace(name)
	if err != nil {
		return err
	}
	if n.Active {
		return nil
	}
	n.Active = true
	return r.PutNamespace(n)
}

func (r *Repository) DeleteNamespace(name string) error {
	if err := r.store.Delete(r.keys.NamespaceConfig(name)); err != nil {
		return fmt.Errorf("catalog: delete namespace %s: %w", name, err)
	}
	return nil
}

// ListNamespaces scans every namespace's own config record. The scan must
// match that record precisely (exactly "{name}/config" under the
// namespaces prefix, nothing deeper) since every other namespace-scoped
// resource's key (owned by internal/rbac: groups, roles, rolebindings;
// and by this package: subscriptions) also ends in "/config".
func (r *Repository) ListNamespaces() ([]Namespace, error) {
	entries, err := r.store.List(r.keys.NamespacesPrefix())
	if err != nil {
		return nil, fmt.Errorf("catalog: scan namespaces: %w", err)
	}

	prefix := r.keys.NamespacesPrefix()
	var namespaces []Namespace
	for key, data := range entries {
		rest := strings.TrimPrefix(key, prefix)
		segments := strings.Split(rest, "/")
		if len(segments) != 2 || segments[1] != "config" {
			continue
		}
		var n Namespace
		if err := json.Unmarshal(data, &n); err != nil {
			return nil, fmt.Errorf("catalog: unmarshal namespace %s: %w", key, err)
		}
		namespaces = append(namespaces, n)
	}
	return namespaces, nil
}

// --- Namespace-scoped subscriptions ---

func (r *Repository) PutNamespaceSubscription(namespace string, sub Subscription) error {
	return store.PutJSON(r.store, r.keys.NamespaceSubscriptionConfig(namespace, sub.StackName), sub)
}

func (r *Repository) GetNamespaceSubscription(namespace, stackName string) (Subscription, error) {
	var sub Subscription
	err := store.GetJSON(r.store, r.keys.NamespaceSubscriptionConfig(namespace, stackName), &sub)
	return sub, err
}

func (r *Repository) ListNamespaceSubscriptions(namespace string) ([]Subscription, error) {
	raw, err := store.ListConfigValues(r.store, r.keys.NamespaceSubscriptionPrefix(namespace))
	if err != nil {
		return nil, err
	}
	subs := make([]Subscription, len(raw))
	for i, data := range raw {
		if err := json.Unmarshal(data, &subs[i]); err != nil {
			return nil, fmt.Errorf("catalog: unmarshal namespace subscription: %w", err)
		}
	}
	return subs, nil
}

// ActivateSubscription marks namespace's subscription to stackName as
// successfully provisioned and reconciled to syncID (the referenced
// stack's own SyncID at the moment of activation). Same trust boundary as
// ActivateNamespace: the public API always writes a subscription
// Active:false/State:init/CurrentSyncID:"", so this is the only path that
// can ever move it to active/success — called exactly once, by
// Reconciler, the first time it observes a subscription still in that
// state.
func (r *Repository) ActivateSubscription(namespace, stackName, syncID string) error {
	sub, err := r.GetNamespaceSubscription(namespace, stackName)
	if err != nil {
		return err
	}
	if sub.Active && sub.State == SubscriptionStateSuccess {
		return nil
	}
	sub.Active = true
	sub.State = SubscriptionStateSuccess
	sub.CurrentSyncID = syncID
	return r.PutNamespaceSubscription(namespace, sub)
}

// SetSubscriptionSyncID updates namespace's subscription to stackName's
// CurrentSyncID to syncID, leaving Active/State untouched — once a
// subscription is active, reconciling it again (see Reconciler) only
// ever moves CurrentSyncID forward, never touches Active again.
func (r *Repository) SetSubscriptionSyncID(namespace, stackName, syncID string) error {
	sub, err := r.GetNamespaceSubscription(namespace, stackName)
	if err != nil {
		return err
	}
	sub.CurrentSyncID = syncID
	return r.PutNamespaceSubscription(namespace, sub)
}

// ListSubscriptionsToStack returns every namespace's subscription to
// stackName, keyed by namespace name — used by Reconciler to find every
// subscription a stack's own SyncID change must reconcile.
func (r *Repository) ListSubscriptionsToStack(stackName string) (map[string]Subscription, error) {
	entries, err := r.store.List(r.keys.NamespacesPrefix())
	if err != nil {
		return nil, fmt.Errorf("catalog: scan namespaces for subscriptions to %s: %w", stackName, err)
	}

	prefix := r.keys.NamespacesPrefix()
	suffix := fmt.Sprintf("/subscriptions/%s/config", stackName)
	result := make(map[string]Subscription)
	for key, data := range entries {
		if !strings.HasSuffix(key, suffix) {
			continue
		}
		namespace := strings.SplitN(strings.TrimPrefix(key, prefix), "/", 2)[0]
		var sub Subscription
		if err := json.Unmarshal(data, &sub); err != nil {
			return nil, fmt.Errorf("catalog: unmarshal subscription %s: %w", key, err)
		}
		result[namespace] = sub
	}
	return result, nil
}

func (r *Repository) DeleteNamespaceSubscription(namespace, stackName string) error {
	if err := r.store.Delete(r.keys.NamespaceSubscriptionConfig(namespace, stackName)); err != nil {
		return fmt.Errorf("catalog: delete subscription %s/%s: %w", namespace, stackName, err)
	}
	return nil
}
