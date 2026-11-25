package rbac

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/infrapi/lib/pkg/auth"

	"github.com/infrapi/kayra/internal/identity"
	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// The cluster scope: resources in no namespace, Kayra's own (namespaces,
// apiregistrations, the cluster RBAC objects) and any app's
// (/apis/<api>/<version>/<resource>). They are granted by global cluster
// role bindings, those whose metadata.namespace is "", binding global
// cluster groups to cluster roles, and by the built-in sysadmin binding
// (SetSysadmin). A global binding grants nothing in a namespace, and no
// namespace object ever grants anything cluster-scoped.

// all is the built-in sysadmin binding's one rule.
var all = Rule{Apis: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}

// IsSysadmin reports whether callerGroups hold one of the built-in
// sysadmin binding's groups.
func (r *Repository) IsSysadmin(callerGroups []string) bool {
	return groupsIntersect(callerGroups, r.sysadmin)
}

// ClusterRules are the rules a caller holds on cluster-scoped resources:
// the built-in sysadmin binding's, and the cluster roles of every global
// binding of a global cluster group the caller is a member of.
func (r *Repository) ClusterRules(userID string, callerGroups []string) ([]Rule, error) {
	if identity.IsServiceAccount(userID) {
		return nil, nil // a service account holds nothing cluster-scoped
	}
	if r.IsSysadmin(callerGroups) {
		return []Rule{all}, nil
	}
	groups, err := r.ListClusterGroups()
	if err != nil {
		return nil, err
	}
	var member []string
	for _, g := range groups {
		if g.Metadata.Namespace == "" && groupMatchesCaller(g, userID, callerGroups) {
			member = append(member, g.Name)
		}
	}
	if len(member) == 0 {
		return nil, nil
	}
	bindings, err := r.ListClusterRoleBindings()
	if err != nil {
		return nil, err
	}
	var rules []Rule
	for _, rb := range bindings {
		if rb.Metadata.Namespace != "" || !groupsIntersect(rb.Groups, member) {
			continue
		}
		role, err := r.GetClusterRole(rb.Role)
		if err == store.ErrNotFound {
			continue
		}
		if err != nil {
			return nil, err
		}
		rules = append(rules, role.Rules...)
	}
	return rules, nil
}

// AuthorizeCluster reports whether a caller is granted verb on a
// cluster-scoped resource of api.
func (r *Repository) AuthorizeCluster(userID string, callerGroups []string, api, resource, verb string) (allowed bool, reason string, err error) {
	rules, err := r.ClusterRules(userID, callerGroups)
	if err != nil {
		return false, "", err
	}
	switch {
	case Allows(rules, api, resource, verb):
		return true, "", nil
	case len(rules) == 0:
		return false, "no global cluster role binding binds a cluster group of yours, and you are not a sysadmin", nil
	case !grantsApi(rules, api):
		return false, fmt.Sprintf("your cluster roles do not grant api %q", api), nil
	}
	return false, fmt.Sprintf("your cluster roles grant api %q, but not %q on %q", api, verb, resource), nil
}

// ClusterRequest is a cluster-scoped request taken apart as infrapi/lib's
// auth does it: /apis/<api>/<version>/<resource...>, resource its names
// joined, verb from the method and whether the path ends on an id.
func ClusterRequest(path, method string) (api, resource, verb string, err error) {
	rest, ok := strings.CutPrefix(path, "/apis/")
	if !ok {
		return "", "", "", fmt.Errorf("rbac: %q is not under /apis/", path)
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 3 {
		return "", "", "", fmt.Errorf("rbac: %q has no resource", path)
	}
	resource, hasID, err := auth.ParseResource(parts[2])
	if err != nil {
		return "", "", "", err
	}
	verb, err = auth.VerbFor(method, hasID)
	return parts[0], resource, verb, err
}

// Uncovered is the first permission want grants that have does not, as
// "api resource verb", or "" when have covers all of want: what a caller
// may grant, in a role or a binding, without the escalate or bind verb. A
// "*" in want is covered only by a "*" in have.
func Uncovered(have, want []Rule) string {
	for _, w := range want {
		for _, api := range w.Apis {
			for _, res := range w.Resources {
				for _, verb := range w.Verbs {
					if !Allows(have, api, res, verb) {
						return api + " " + res + " " + verb
					}
				}
			}
		}
	}
	return ""
}

// NamespaceRules are the rules a caller holds in namespace: those of the
// cluster bindings scoped to it, and of its own rolebindings binding a
// group of the namespace the caller is a member of.
func (r *Repository) NamespaceRules(userID string, callerGroups []string, namespace string) ([]Rule, error) {
	var rules []Rule
	clusterGroups, err := r.clusterGroupsMatching(userID, callerGroups)
	if err != nil {
		return nil, err
	}
	bindings, err := r.ListClusterRoleBindings()
	if err != nil {
		return nil, err
	}
	for _, rb := range bindings {
		if rb.Metadata.Namespace != namespace || !groupsIntersect(rb.Groups, clusterGroups) {
			continue
		}
		role, err := r.GetClusterRole(rb.Role)
		if err == store.ErrNotFound {
			continue
		}
		if err != nil {
			return nil, err
		}
		rules = append(rules, role.Rules...)
	}
	member, err := r.namespaceGroupsMatching(namespace, userID, callerGroups)
	if err != nil {
		return nil, err
	}
	nsBindings, err := r.ListNamespaceRoleBindings(namespace)
	if err != nil {
		return nil, err
	}
	for _, rb := range nsBindings {
		if !groupsIntersect(rb.Groups, member) {
			continue
		}
		role, err := r.GetNamespaceRole(namespace, rb.Role)
		if err == store.ErrNotFound {
			continue
		}
		if err != nil {
			return nil, err
		}
		rules = append(rules, role.Rules...)
	}
	return rules, nil
}

// The verbs that lift the anti-escalation rule: escalate on a roles
// resource writes a role granting more than its writer holds, bind on a
// rolebindings resource binds one.
const (
	VerbEscalate = "escalate"
	VerbBind     = "bind"
)

// checkGrant refuses a role, or a binding to it, that grants what the
// caller does not hold (have), unless have grants verb (escalate or bind)
// on resource of the authorization API.
func checkGrant(have, want []Rule, resource, verb, origin string) *liberrors.Error {
	if Allows(have, AuthorizationAPI, resource, verb) {
		return nil
	}
	if missing := Uncovered(have, want); missing != "" {
		return liberrors.New(http.StatusForbidden, origin, "it grants %s, which you do not hold", missing).
			WithSolution("grant only what you hold, or ask for %q on %s", verb, resource)
	}
	return nil
}
