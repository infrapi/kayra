package rbac

import (
	"encoding/json"
	"fmt"

	"github.com/infrapi/kayra/internal/store"
)

// Repository persists groups, roles and role bindings under the etcd/local
// key layout internal/store.Keys defines.
type Repository struct {
	store store.Store
	keys  store.Keys
}

// NewRepository returns a Repository backed by s, addressed through keys.
func NewRepository(s store.Store, keys store.Keys) *Repository {
	return &Repository{store: s, keys: keys}
}

// Put* methods stamp their argument's created_at/updated_at in place
// (store.PutObject), so callers pass a pointer and can return it as-is.
//
// getJSON/listConfigValues delegate to internal/store's generic
// JSON-record helpers — shared with internal/catalog, which persists
// ApiRegistration/Namespace/Subscription under the same "/config" convention.
func getJSON(s store.Store, key string, v any) error {
	return store.GetJSON(s, key, v)
}

func listConfigValues(s store.Store, prefix string) ([][]byte, error) {
	return store.ListConfigValues(s, prefix)
}

// --- Cluster scope ---

func (r *Repository) PutClusterGroup(g *Group) error {
	return store.PutObject(r.store, r.keys.ClusterGroupConfig(g.Name), g)
}

func (r *Repository) GetClusterGroup(name string) (Group, error) {
	var g Group
	err := getJSON(r.store, r.keys.ClusterGroupConfig(name), &g)
	return g, err
}

func (r *Repository) ListClusterGroups() ([]Group, error) {
	raw, err := listConfigValues(r.store, r.keys.ClusterGroupPrefix())
	if err != nil {
		return nil, err
	}
	groups := make([]Group, len(raw))
	for i, data := range raw {
		if err := json.Unmarshal(data, &groups[i]); err != nil {
			return nil, fmt.Errorf("rbac: unmarshal cluster group: %w", err)
		}
	}
	return groups, nil
}

// DeleteClusterGroup removes a cluster group's config.
func (r *Repository) DeleteClusterGroup(name string) error {
	if err := r.store.Delete(r.keys.ClusterGroupConfig(name)); err != nil {
		return fmt.Errorf("rbac: delete cluster group %s: %w", name, err)
	}
	return nil
}

func (r *Repository) PutClusterRole(role *Role) error {
	return store.PutObject(r.store, r.keys.ClusterRoleConfig(role.Name), role)
}

func (r *Repository) GetClusterRole(name string) (Role, error) {
	var role Role
	err := getJSON(r.store, r.keys.ClusterRoleConfig(name), &role)
	return role, err
}

func (r *Repository) ListClusterRoles() ([]Role, error) {
	raw, err := listConfigValues(r.store, r.keys.ClusterRolePrefix())
	if err != nil {
		return nil, err
	}
	roles := make([]Role, len(raw))
	for i, data := range raw {
		if err := json.Unmarshal(data, &roles[i]); err != nil {
			return nil, fmt.Errorf("rbac: unmarshal cluster role: %w", err)
		}
	}
	return roles, nil
}

func (r *Repository) DeleteClusterRole(name string) error {
	if err := r.store.Delete(r.keys.ClusterRoleConfig(name)); err != nil {
		return fmt.Errorf("rbac: delete cluster role %s: %w", name, err)
	}
	return nil
}

func (r *Repository) PutClusterRoleBinding(rb *RoleBinding) error {
	return store.PutObject(r.store, r.keys.ClusterRoleBindingConfig(rb.Name), rb)
}

func (r *Repository) GetClusterRoleBinding(name string) (RoleBinding, error) {
	var rb RoleBinding
	err := getJSON(r.store, r.keys.ClusterRoleBindingConfig(name), &rb)
	return rb, err
}

func (r *Repository) ListClusterRoleBindings() ([]RoleBinding, error) {
	raw, err := listConfigValues(r.store, r.keys.ClusterRoleBindingPrefix())
	if err != nil {
		return nil, err
	}
	bindings := make([]RoleBinding, len(raw))
	for i, data := range raw {
		if err := json.Unmarshal(data, &bindings[i]); err != nil {
			return nil, fmt.Errorf("rbac: unmarshal cluster rolebinding: %w", err)
		}
	}
	return bindings, nil
}

func (r *Repository) DeleteClusterRoleBinding(name string) error {
	if err := r.store.Delete(r.keys.ClusterRoleBindingConfig(name)); err != nil {
		return fmt.Errorf("rbac: delete cluster rolebinding %s: %w", name, err)
	}
	return nil
}

// --- Namespace scope ---

func (r *Repository) PutNamespaceGroup(namespace string, g *Group) error {
	return store.PutObject(r.store, r.keys.NamespaceGroupConfig(namespace, g.Name), g)
}

func (r *Repository) GetNamespaceGroup(namespace, name string) (Group, error) {
	var g Group
	err := getJSON(r.store, r.keys.NamespaceGroupConfig(namespace, name), &g)
	return g, err
}

func (r *Repository) ListNamespaceGroups(namespace string) ([]Group, error) {
	raw, err := listConfigValues(r.store, r.keys.NamespaceGroupPrefix(namespace))
	if err != nil {
		return nil, err
	}
	groups := make([]Group, len(raw))
	for i, data := range raw {
		if err := json.Unmarshal(data, &groups[i]); err != nil {
			return nil, fmt.Errorf("rbac: unmarshal namespace group: %w", err)
		}
	}
	return groups, nil
}

// DeleteNamespaceGroup removes a namespace group's config.
func (r *Repository) DeleteNamespaceGroup(namespace, name string) error {
	if err := r.store.Delete(r.keys.NamespaceGroupConfig(namespace, name)); err != nil {
		return fmt.Errorf("rbac: delete namespace group %s/%s: %w", namespace, name, err)
	}
	return nil
}

func (r *Repository) PutNamespaceRole(namespace string, role *Role) error {
	return store.PutObject(r.store, r.keys.NamespaceRoleConfig(namespace, role.Name), role)
}

func (r *Repository) GetNamespaceRole(namespace, name string) (Role, error) {
	var role Role
	err := getJSON(r.store, r.keys.NamespaceRoleConfig(namespace, name), &role)
	return role, err
}

func (r *Repository) ListNamespaceRoles(namespace string) ([]Role, error) {
	raw, err := listConfigValues(r.store, r.keys.NamespaceRolePrefix(namespace))
	if err != nil {
		return nil, err
	}
	roles := make([]Role, len(raw))
	for i, data := range raw {
		if err := json.Unmarshal(data, &roles[i]); err != nil {
			return nil, fmt.Errorf("rbac: unmarshal namespace role: %w", err)
		}
	}
	return roles, nil
}

func (r *Repository) DeleteNamespaceRole(namespace, name string) error {
	if err := r.store.Delete(r.keys.NamespaceRoleConfig(namespace, name)); err != nil {
		return fmt.Errorf("rbac: delete namespace role %s/%s: %w", namespace, name, err)
	}
	return nil
}

func (r *Repository) PutNamespaceRoleBinding(namespace string, rb *RoleBinding) error {
	return store.PutObject(r.store, r.keys.NamespaceRoleBindingConfig(namespace, rb.Name), rb)
}

func (r *Repository) GetNamespaceRoleBinding(namespace, name string) (RoleBinding, error) {
	var rb RoleBinding
	err := getJSON(r.store, r.keys.NamespaceRoleBindingConfig(namespace, name), &rb)
	return rb, err
}

func (r *Repository) ListNamespaceRoleBindings(namespace string) ([]RoleBinding, error) {
	raw, err := listConfigValues(r.store, r.keys.NamespaceRoleBindingPrefix(namespace))
	if err != nil {
		return nil, err
	}
	bindings := make([]RoleBinding, len(raw))
	for i, data := range raw {
		if err := json.Unmarshal(data, &bindings[i]); err != nil {
			return nil, fmt.Errorf("rbac: unmarshal namespace rolebinding: %w", err)
		}
	}
	return bindings, nil
}

func (r *Repository) DeleteNamespaceRoleBinding(namespace, name string) error {
	if err := r.store.Delete(r.keys.NamespaceRoleBindingConfig(namespace, name)); err != nil {
		return fmt.Errorf("rbac: delete namespace rolebinding %s/%s: %w", namespace, name, err)
	}
	return nil
}
