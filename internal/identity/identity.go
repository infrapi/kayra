// Package identity names the identities Kayra issues itself, as opposed to
// the humans an external provider vouches for: a namespace's service
// accounts, system:serviceaccount:<namespace>:<name>, and (later) an API's
// own, system:api:<group>. Every subject under the reserved "system:"
// prefix is one of Kayra's: a provider's user id with that prefix is
// refused (middleware), so no directory account can pose as one.
package identity

import (
	"regexp"
	"strings"
)

// Reserved starts every subject Kayra issues itself.
const Reserved = "system:"

// The kinds of caller an AuthContext carries.
const (
	// KindUser is a human, vouched for by a provider.
	KindUser = "user"
	// KindServiceAccount is a namespace's service account.
	KindServiceAccount = "serviceaccount"
)

// ServiceAccountPrefix starts a service account's subject.
const ServiceAccountPrefix = Reserved + "serviceaccount:"

// ServiceAccountsGroup is the group of every service account, and
// ServiceAccountsGroup + ":<namespace>" that of a namespace's.
const ServiceAccountsGroup = Reserved + "serviceaccounts"

// name is a DNS label: a service account's name, a namespace's.
var name = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// IsReserved tells a subject or group under the reserved prefix.
func IsReserved(s string) bool { return strings.HasPrefix(s, Reserved) }

// ValidName tells a valid service account name: a DNS label.
func ValidName(s string) bool { return name.MatchString(s) }

// ServiceAccount is the subject of namespace's service account name.
func ServiceAccount(namespace, name string) string {
	return ServiceAccountPrefix + namespace + ":" + name
}

// ParseServiceAccount splits a service account's subject into its
// namespace and name; ok is false for any other subject.
func ParseServiceAccount(subject string) (namespace, name string, ok bool) {
	rest, ok := strings.CutPrefix(subject, ServiceAccountPrefix)
	if !ok {
		return "", "", false
	}
	namespace, name, ok = strings.Cut(rest, ":")
	if !ok || !ValidName(namespace) || !ValidName(name) {
		return "", "", false
	}
	return namespace, name, true
}

// NamespaceServiceAccounts is the group of namespace's service accounts.
func NamespaceServiceAccounts(namespace string) string {
	return ServiceAccountsGroup + ":" + namespace
}

// ServiceAccountGroups are the groups a service account of namespace is
// in: every service account's, and its namespace's.
func ServiceAccountGroups(namespace string) []string {
	return []string{ServiceAccountsGroup, NamespaceServiceAccounts(namespace)}
}
