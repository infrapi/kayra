// Package authz resolves a user id to their attributes and group
// membership, against either a real LDAP directory or the "dev: local:"
// fixture the spec calls out for testing without one, and caches the
// result in the configured store.
package authz

import "errors"

// UserInfo is what an Authorizer resolves a user id into.
type UserInfo struct {
	ID         string            `json:"id"`
	Attributes map[string]string `json:"attributes"`
	Groups     []string          `json:"groups"`
}

// Authorizer resolves a user id to their directory info. This is every
// authorizations.<name> entry's full contract: authorization decisions
// are made against the groups a caller's own token already carries (see
// rbac.CanManageNamespaceRBAC), never against a separately synced member
// list, so resolving a group's membership independently of a user is not
// part of this package's job.
type Authorizer interface {
	ResolveUser(userID string) (UserInfo, error)
}

// PasswordAuthenticator verifies a username/password against the backend
// and, on success, returns the same UserInfo ResolveUser would — real
// identity and group membership, never an operator-asserted claim. Used
// to mint self-issued tokens from a real login instead of trusting
// whatever groups the caller types in.
type PasswordAuthenticator interface {
	Login(username, password string) (UserInfo, error)
}

// ErrNotFound is returned by ResolveUser when the user does not exist in
// the backend.
var ErrNotFound = errors.New("authz: not found")

// Compile-time checks: both backends support password login, so
// token-minting can embed real resolved groups rather than an
// operator-asserted claim, in both production (LDAP) and dev/test
// (devlocal fixture).
var (
	_ PasswordAuthenticator = (*LDAPAuthorizer)(nil)
	_ PasswordAuthenticator = (*DevLocalAuthorizer)(nil)
)
