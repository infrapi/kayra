// Package catalog stores and serves the infrastructure catalog ported
// from the legacy Postgres/GORM tool: Stack (a platform+
// region-scoped infra component definition), Namespace (that tool's
// "Tenant" — a namespace IS a tenant, not a separate thing joined by a
// name), and Subscription (linking a namespace to a Stack by name).
//
// It depends on internal/rbac only for rbac.RequireClusterRBAC/
// rbac.Repository: Subscription is gated by the exact same cluster RBAC
// check as every other namespace resource, so there's no reason to
// duplicate that decision here — the dependency runs catalog -> rbac,
// never the other way.
package catalog

// StackAPI and NamespaceAPI name this package's own two API groups —
// mirroring internal/rbac.AuthorizationAPI/SubscriptionAPI, though
// neither is checked against a stored Rule (both are gated by
// middleware.SysadminGate alone, see RegisterStackRoutes and
// RegisterNamespaceCollectionRoutes). "example.com" is a placeholder:
// SetAPIDomain rebuilds both from a deployment's own domain
// (config.AppConfig.APIDomain) — call it once, before either Register
// function.
var (
	StackAPI     = "catalog.example.com"
	NamespaceAPI = "apps.example.com"
)

// SetAPIDomain rebuilds StackAPI and NamespaceAPI as "catalog.<domain>"
// and "apps.<domain>".
func SetAPIDomain(domain string) {
	StackAPI = "catalog." + domain
	NamespaceAPI = "apps." + domain
}

// StackRef identifies one Stack by its full composite key: the legacy
// Postgres model allowed a dependency to reference a stack in any
// platform/region, not just the owning stack's own scope, so this is
// never a bare name.
type StackRef struct {
	Platform string `json:"platform" yaml:"platform"`
	Region   string `json:"region" yaml:"region"`
	Name     string `json:"name" yaml:"name"`
}

// Stack is a cluster-wide infrastructure component definition scoped to
// one platform+region (e.g. "vault", "pki" in "sandbox"/"eu-west-1"),
// ported from the legacy Postgres "stacks" table.
// DependsOn replaces that table's separate "dependencies" table: a
// dependency carried no data beyond the two stack references, so it is
// folded directly into the owning Stack.
type Stack struct {
	Name        string     `json:"name" yaml:"name"`
	Platform    string     `json:"platform" yaml:"platform"`
	Region      string     `json:"region" yaml:"region"`
	Active      bool       `json:"active" yaml:"active"`
	Upstream    bool       `json:"upstream" yaml:"upstream"`
	Downstream  bool       `json:"downstream" yaml:"downstream"`
	Owner       string     `json:"owner" yaml:"owner"`
	Description string     `json:"description" yaml:"description"`
	DependsOn   []StackRef `json:"depends_on" yaml:"depends_on"`
	// SyncID is the stack owner's reconcile trigger: bumping it (to any
	// new value, e.g. a timestamp or a release id) is what tells every
	// subscription already active against this stack to reconcile — see
	// Reconciler. It carries no meaning on its own, only via inequality
	// against a Subscription's own CurrentSyncID.
	SyncID string `json:"sync_id" yaml:"sync_id"`
	// CanaryNamespaces, when non-empty, restricts the current SyncID's
	// automatic reconcile (see Reconciler's handleStackPut) to just these
	// namespaces — every other active subscriber is left pending until a
	// release sync (PUT .../stacks/:name/sync with no canary_namespaces)
	// fans the same SyncID out to them too. It's pipeline state for an
	// in-progress canary rollout, not a spec field a caller edits
	// directly: only PUT .../stacks/:name/sync ever sets or clears it —
	// the general PUT .../stacks/:name leaves whatever is already here
	// untouched, so an unrelated edit mid-rollout can't silently finish
	// or restart it.
	CanaryNamespaces []string `json:"canary_namespaces" yaml:"canary_namespaces"`
	// Mode picks how Reconciler's reconcile action for this stack is
	// actually carried out: a free-form key into reconciler.mode in
	// kayra.yaml (config.ReconcilerConfig.Mode) — "trigger" and "api" in
	// every example, but any name works, since that's just a map. Falls
	// back to reconciler.default_mode when empty; reconcile fails only
	// when neither resolves to anything at all.
	Mode string `json:"mode" yaml:"mode"`
}

// Subscription links a namespace to one Stack by name, ported from the
// legacy "subscriptions" table. Unlike Stack itself, it carries no
// platform/region: this deployment runs in exactly one platform/region
// (INFRAPI_APP_PLATFORM/_REGION), so "subscribed to stack X" can only
// ever mean the X in this deployment's own platform/region — there is no
// second one to disambiguate against.
type Subscription struct {
	StackName string `json:"stack_name" yaml:"stack_name"`
	Active    bool   `json:"active" yaml:"active"`
	// State is one of SubscriptionStateInit/Success/Error/Undef. Stored
	// as a string, unlike the legacy model's raw persisted int ordinal:
	// JSON carries no ordinal-stability requirement, so there is no
	// reason to keep one.
	State string `json:"state" yaml:"state"`
	// CurrentSyncID tracks which of the stack's own SyncID values this
	// subscription was last reconciled to: empty until
	// Reconciler.ensureReconciled reconciles it successfully, and only
	// ever advanced by a further successful reconcile after that — never
	// written optimistically ahead of reconcile actually succeeding. No
	// omitempty: a subscription with nothing to report here still reports
	// it, as "" rather than a field that silently isn't there — callers
	// should never have to treat "absent" and "empty" as two different
	// things. This is the only sync id persisted on the subscription
	// itself — the stack's own *current* SyncID (what a caller would
	// compare it against) is never copied here; it's read fresh from the
	// stack at response time instead (see subscriptionResponse in
	// handlers_subscription.go), so it can never go stale between
	// Reconciler runs.
	CurrentSyncID string `json:"current_sync_id" yaml:"current_sync_id"`
}

const (
	SubscriptionStateInit    = "init"
	SubscriptionStateSuccess = "success"
	SubscriptionStateError   = "error"
	SubscriptionStateUndef   = "undef"
)

// ValidSubscriptionState reports whether state is one of the four
// allowed values.
func ValidSubscriptionState(state string) bool {
	switch state {
	case SubscriptionStateInit, SubscriptionStateSuccess, SubscriptionStateError, SubscriptionStateUndef:
		return true
	default:
		return false
	}
}

// Namespace is itself the legacy model's "Tenant": a namespace and a
// tenant are the same thing, not two things joined by a name. Name and
// whether it's active both live directly on the namespace record —
// there is no separate tenant resource or URL segment.
type Namespace struct {
	Name   string `json:"name"`
	Active bool   `json:"active"`
}
