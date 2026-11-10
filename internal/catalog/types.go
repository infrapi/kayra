// Package catalog stores and serves the infrastructure catalog ported
// from the legacy Postgres/GORM tool: ApiRegistration (a platform+
// region-scoped record declaring that some API group exists and who
// owns it — Kayra itself never implements the API it names, only
// tracks and notifies on it), Namespace (that tool's "Tenant" — a
// namespace IS a tenant, not a separate thing joined by a name), and
// Subscription (linking a namespace to an ApiRegistration by name).
//
// It depends on internal/rbac only for rbac.RequireClusterRBAC/
// rbac.Repository: Subscription is gated by the exact same cluster RBAC
// check as every other namespace resource, so there's no reason to
// duplicate that decision here — the dependency runs catalog -> rbac,
// never the other way.
package catalog

// CatalogAPI and NamespaceAPI name this package's two API groups,
// laid out exactly like rbac.AuthorizationAPI: CatalogAPI's
// cluster-scoped resource (apiregistrations) is gated by
// middleware.SysadminGate alone, never checked against a stored Rule
// (see RegisterApiRegistrationRoutes), while its namespace-scoped one
// (subscriptions) is checked against CatalogAPI via
// rbac.RequireClusterRBAC (see RegisterNamespaceRoutes) — so a Rule
// granting CatalogAPI "*" covers subscriptions only, just as one granting
// AuthorizationAPI "*" never covers cluster roles. NamespaceAPI
// (namespaces) is SysadminGate-only too (see
// RegisterNamespaceCollectionRoutes). "example.com" is a placeholder:
// SetAPIDomain rebuilds both from a deployment's own domain
// (config.AppConfig.APIDomain) — call it once, before any Register
// function or any stored Rule is compared against these.
var (
	CatalogAPI   = "catalog.example.com"
	NamespaceAPI = "apps.example.com"
)

// SetAPIDomain rebuilds CatalogAPI and NamespaceAPI as "catalog.<domain>"
// and "apps.<domain>".
func SetAPIDomain(domain string) {
	CatalogAPI = "catalog." + domain
	NamespaceAPI = "apps." + domain
}

// ApiRegistrationRef identifies one ApiRegistration by its full
// composite key: the legacy Postgres model allowed a dependency to
// reference a registration in any platform/region, not just the owning
// one's own scope, so this is never a bare name.
type ApiRegistrationRef struct {
	Platform string `json:"platform" yaml:"platform"`
	Region   string `json:"region" yaml:"region"`
	Name     string `json:"name" yaml:"name"`
}

// ApiRegistration declares that an API group exists, scoped to one
// platform+region (e.g. "vault", "pki" in "sandbox"/"eu-west-1"),
// ported from the legacy Postgres "stacks" table. Kayra never serves
// the API it names itself — whatever team owns it implements it as its
// own service (using infrapi/lib, like any other app, to ask Kayra's
// own /apis/authorization.<domain>/v1/check for RBAC) and is notified
// of changes through Reconciler, agnostic of however that team's own
// API gateway (APISIX, Envoy, Kong, ...) actually routes to it.
// DependsOn replaces the legacy model's separate "dependencies" table:
// a dependency carried no data beyond the two registration references,
// so it is folded directly into the owning ApiRegistration.
type ApiRegistration struct {
	// Name is the api's id: its long name, the full API group URN it is
	// reachable under (e.g. "compute.example.com") — the only name a
	// Subscription, a /v1/check request or a Role rule ever refers to it
	// by. See IsLongApiName.
	Name string `json:"name" yaml:"name"`
	// ShortName is an optional single-label alias (e.g. "compute"),
	// unique within this platform/region, for display and templating
	// only (see subscriptionTemplateData.ShortName): it never identifies
	// the registration anywhere — a Subscription naming it is refused.
	ShortName   string               `json:"short_name" yaml:"short_name"`
	Platform    string               `json:"platform" yaml:"platform"`
	Region      string               `json:"region" yaml:"region"`
	Active      bool                 `json:"active" yaml:"active"`
	Upstream    bool                 `json:"upstream" yaml:"upstream"`
	Downstream  bool                 `json:"downstream" yaml:"downstream"`
	Owner       string               `json:"owner" yaml:"owner"`
	Description string               `json:"description" yaml:"description"`
	DependsOn   []ApiRegistrationRef `json:"depends_on" yaml:"depends_on"`
	// SyncID is the registration owner's reconcile trigger: bumping it
	// (to any new value, e.g. a timestamp or a release id) is what
	// tells every subscription already active against it to reconcile
	// — see Reconciler. It carries no meaning on its own, only via
	// inequality against a Subscription's own CurrentSyncID.
	SyncID string `json:"sync_id" yaml:"sync_id"`
	// CanaryNamespaces, when non-empty, restricts the current SyncID's
	// automatic reconcile (see Reconciler's handleApiRegistrationPut) to
	// just these namespaces — every other active subscriber is left
	// exactly as it was, pending — until a release sync (PUT
	// .../apiregistrations/:name/sync with no canary_namespaces) fans
	// the same SyncID out to them too. It's pipeline state for an
	// in-progress canary rollout, not a spec field a caller edits
	// directly: only PUT .../sync ever sets or clears it — the general
	// PUT .../apiregistrations/:name leaves whatever is already here
	// untouched, so an unrelated edit mid-rollout can't silently finish
	// or restart it.
	CanaryNamespaces []string `json:"canary_namespaces" yaml:"canary_namespaces"`
	// Mode picks how Reconciler's reconcile action for this registration
	// is actually carried out: a free-form key into reconciler.mode in
	// kayra.yaml (config.ReconcilerConfig.Mode) — "trigger" and "api" in
	// every example, but any name works, since that's just a map. Falls
	// back to reconciler.default_mode when empty; reconcile fails only
	// when neither resolves to anything at all.
	Mode string `json:"mode" yaml:"mode"`
}

// Subscription links a namespace to one ApiRegistration by its long
// name (ApiRegistration.Name, never its ShortName), ported
// from the legacy "subscriptions" table. Unlike ApiRegistration itself,
// it carries no platform/region: this deployment runs in exactly one
// platform/region (INFRAPI_APP_PLATFORM/_REGION), so "subscribed to api
// X" can only ever mean the X in this deployment's own platform/region
// — there is no second one to disambiguate against.
type Subscription struct {
	ApiName string `json:"api" yaml:"api"`
	Active  bool   `json:"active" yaml:"active"`
	// State is one of SubscriptionStateInit/Success/Error/Undef. Stored
	// as a string, unlike the legacy model's raw persisted int ordinal:
	// JSON carries no ordinal-stability requirement, so there is no
	// reason to keep one.
	State string `json:"state" yaml:"state"`
	// CurrentSyncID tracks which of the registration's own SyncID
	// values this subscription was last reconciled to: empty until
	// Reconciler.ensureReconciled reconciles it successfully, and only
	// ever advanced by a further successful reconcile after that — never
	// written optimistically ahead of reconcile actually succeeding. No
	// omitempty: a subscription with nothing to report here still reports
	// it, as "" rather than a field that silently isn't there — callers
	// should never have to treat "absent" and "empty" as two different
	// things. This is the only sync id persisted on the subscription
	// itself — the registration's own *current* SyncID (what a caller
	// would compare it against) is never copied here; it's read fresh
	// at response time instead (see subscriptionResponse in
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
