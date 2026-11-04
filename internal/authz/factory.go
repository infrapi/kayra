package authz

import (
	"fmt"

	"github.com/infrapi/kayra/internal/config"
)

// New builds the Authorizer described by cfg, picking ldap or local
// depending on which is set. Validate() on the config guarantees exactly
// one of them is non-nil.
func New(cfg config.AuthorizationBackend) (Authorizer, error) {
	switch {
	case cfg.Ldap != nil:
		return NewLDAPAuthorizer(cfg.Ldap)
	case cfg.Local != nil:
		return NewDevLocalAuthorizer(cfg.Local)
	default:
		return nil, fmt.Errorf("authz: backend has neither ldap nor local configured")
	}
}
