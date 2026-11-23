package rbac

import (
	"slices"

	"github.com/infrapi/kayra/internal/identity"
)

// catalogAPI is the catalog's group, catalog.<domain> (see SetAPIDomain):
// rbac cannot import catalog, which imports it.
var catalogAPI = "catalog.infrapi.io"

// ImplicitAPI tells a request an API may always make about itself,
// whatever the RBAC: caller is system:api:X, and the request reads X's own
// registration (get apiregistrations X) or its status, the sync state of
// every namespace subscribed to it (apiregistrations/status X). name is
// the object the request names, the route's :name. Anything else an API
// does is decided by the RBAC: a group naming it in apis.
func ImplicitAPI(caller, api, resource, verb, name string) bool {
	group, ok := identity.ParseAPI(caller)
	if !ok || name != group || api != catalogAPI {
		return false
	}
	return (verb == "get" || verb == "list") && slices.Contains([]string{"apiregistrations", "apiregistrations/status"}, resource)
}
