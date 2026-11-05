package store

import "fmt"

// Keys builds every etcd/local key path Kayra uses, from a single
// configured prefix (default "/kayra"), so the layout lives in one place.
type Keys struct {
	Prefix string
}

// NewKeys returns a Keys rooted at prefix, defaulting to "/kayra" when
// prefix is empty.
func NewKeys(prefix string) Keys {
	if prefix == "" {
		prefix = "/kayra"
	}
	return Keys{Prefix: prefix}
}

// AuthCache is where a provider's fetched JWKS keys are cached.
func (k Keys) AuthCache(provider string) string {
	return fmt.Sprintf("%s/cache/authentifications/%s", k.Prefix, provider)
}

// UserCache is where a resolved user's attributes+groups are cached, scoped
// by the authorization backend that resolved them.
func (k Keys) UserCache(authz, userID string) string {
	return fmt.Sprintf("%s/cache/users/%s/%s", k.Prefix, authz, userID)
}

// AuthCachePrefix covers every provider's cached JWKS keys, for clearing
// them all at once.
func (k Keys) AuthCachePrefix() string {
	return fmt.Sprintf("%s/cache/authentifications/", k.Prefix)
}

// UserCachePrefix covers every cached user, across every authorization
// backend, for clearing them all at once.
func (k Keys) UserCachePrefix() string {
	return fmt.Sprintf("%s/cache/users/", k.Prefix)
}

// UserCacheAuthzPrefix covers every cached user resolved through one
// authorization backend, for clearing just that backend's entries.
func (k Keys) UserCacheAuthzPrefix(authz string) string {
	return fmt.Sprintf("%s/cache/users/%s/", k.Prefix, authz)
}

// ClusterGroupConfig is a cluster-level group's definition.
func (k Keys) ClusterGroupConfig(name string) string {
	return fmt.Sprintf("%s/cluster/groups/%s/config", k.Prefix, name)
}

// ClusterGroupPrefix lists every cluster-level group.
func (k Keys) ClusterGroupPrefix() string {
	return fmt.Sprintf("%s/cluster/groups/", k.Prefix)
}

// ClusterRoleConfig is a cluster-level role's definition.
func (k Keys) ClusterRoleConfig(name string) string {
	return fmt.Sprintf("%s/cluster/roles/%s/config", k.Prefix, name)
}

// ClusterRolePrefix lists every cluster-level role.
func (k Keys) ClusterRolePrefix() string {
	return fmt.Sprintf("%s/cluster/roles/", k.Prefix)
}

// ClusterRoleBindingConfig is a cluster-level role binding's definition.
func (k Keys) ClusterRoleBindingConfig(name string) string {
	return fmt.Sprintf("%s/cluster/rolebindings/%s/config", k.Prefix, name)
}

// ClusterRoleBindingPrefix lists every cluster-level role binding.
func (k Keys) ClusterRoleBindingPrefix() string {
	return fmt.Sprintf("%s/cluster/rolebindings/", k.Prefix)
}

// NamespaceGroupConfig is a namespace-scoped group's definition.
func (k Keys) NamespaceGroupConfig(namespace, name string) string {
	return fmt.Sprintf("%s/namespaces/%s/groups/%s/config", k.Prefix, namespace, name)
}

// NamespaceGroupPrefix lists every group in namespace.
func (k Keys) NamespaceGroupPrefix(namespace string) string {
	return fmt.Sprintf("%s/namespaces/%s/groups/", k.Prefix, namespace)
}

// NamespaceRoleConfig is a namespace-scoped role's definition.
func (k Keys) NamespaceRoleConfig(namespace, name string) string {
	return fmt.Sprintf("%s/namespaces/%s/roles/%s/config", k.Prefix, namespace, name)
}

// NamespaceRolePrefix lists every role in namespace.
func (k Keys) NamespaceRolePrefix(namespace string) string {
	return fmt.Sprintf("%s/namespaces/%s/roles/", k.Prefix, namespace)
}

// NamespaceRoleBindingConfig is a namespace-scoped role binding's definition.
func (k Keys) NamespaceRoleBindingConfig(namespace, name string) string {
	return fmt.Sprintf("%s/namespaces/%s/rolebindings/%s/config", k.Prefix, namespace, name)
}

// NamespaceRoleBindingPrefix lists every role binding in namespace.
func (k Keys) NamespaceRoleBindingPrefix(namespace string) string {
	return fmt.Sprintf("%s/namespaces/%s/rolebindings/", k.Prefix, namespace)
}

// ClusterApiRegistrationConfig is a cluster-level API registration's
// definition, scoped by platform and region.
func (k Keys) ClusterApiRegistrationConfig(platform, region, name string) string {
	return fmt.Sprintf("%s/cluster/apiregistrations/%s/%s/%s/config", k.Prefix, platform, region, name)
}

// ClusterApiRegistrationPrefix lists every cluster-level API
// registration, across every platform and region.
func (k Keys) ClusterApiRegistrationPrefix() string {
	return fmt.Sprintf("%s/cluster/apiregistrations/", k.Prefix)
}

// NamespaceConfig is a namespace's own record — its active flag (the
// legacy model's "Tenant": a namespace IS a tenant, not a separate thing
// alongside one).
func (k Keys) NamespaceConfig(namespace string) string {
	return fmt.Sprintf("%s/namespaces/%s/config", k.Prefix, namespace)
}

// NamespacesPrefix covers every namespace's entire resource tree (its own
// config, groups, roles, rolebindings, subscriptions, ...), for scans
// that must look across every namespace at once (listing every
// namespace, or checking whether any namespace still subscribes to an
// api registration before deleting it).
func (k Keys) NamespacesPrefix() string {
	return fmt.Sprintf("%s/namespaces/", k.Prefix)
}

// NamespaceSubscriptionConfig is one namespace's subscription to an API
// registration by name. Unlike ApiRegistration itself, a subscription
// carries no platform/region of its own: this deployment runs in
// exactly one platform/region (INFRAPI_APP_PLATFORM/_REGION), so a
// subscription can only ever mean "the registration named apiName in
// this deployment's own platform/region."
func (k Keys) NamespaceSubscriptionConfig(namespace, apiName string) string {
	return fmt.Sprintf("%s/namespaces/%s/subscriptions/%s/config", k.Prefix, namespace, apiName)
}

// NamespaceSubscriptionPrefix lists every subscription in namespace.
func (k Keys) NamespaceSubscriptionPrefix(namespace string) string {
	return fmt.Sprintf("%s/namespaces/%s/subscriptions/", k.Prefix, namespace)
}

// PatToken is where an encrypted personal access token record lives, keyed
// by the hash of the opaque token value, never the token itself.
func (k Keys) PatToken(hash string) string {
	return fmt.Sprintf("%s/tokens/pat/%s", k.Prefix, hash)
}

// PatKeypair is where the auto-generated PAT encryption keypair is persisted
// when the config does not point at one on disk.
func (k Keys) PatKeypair() string {
	return fmt.Sprintf("%s/keys/pat", k.Prefix)
}

// OAuth2BrokerState is where oauth2broker stashes one in-flight CLI
// login's own redirect_uri/state while the browser is away at the real
// provider (Okta, say) — see internal/oauth2broker. Keyed by a random
// id, never the CLI's own state value, so a collision there can't leak
// one login into another's lookup.
func (k Keys) OAuth2BrokerState(id string) string {
	return fmt.Sprintf("%s/oauth2broker/%s", k.Prefix, id)
}

// ReconcilerNamespaceLock is the JobLocker key guarding one namespace's
// initial activation, so every kayra reconciler process sharing this
// store agrees on which one of them actually runs it for a given
// namespace at a time — see catalog.Reconciler.
func (k Keys) ReconcilerNamespaceLock(name string) string {
	return fmt.Sprintf("%s/locks/reconciler/namespaces/%s", k.Prefix, name)
}

// ReconcilerSubscriptionLock is the JobLocker key guarding one namespace's
// subscription to one API registration — its initial activation and
// every later reconcile — so every kayra reconciler process sharing
// this store agrees on which one of them actually reconciles it at a
// time, rather than each redundantly reacting to the same watch event
// — see catalog.Reconciler.
func (k Keys) ReconcilerSubscriptionLock(namespace, apiName string) string {
	return fmt.Sprintf("%s/locks/reconciler/namespaces/%s/subscriptions/%s", k.Prefix, namespace, apiName)
}
