// Package identity names the identities Kayra issues itself, as opposed to
// the humans an external provider vouches for: a namespace's service
// accounts, system:serviceaccount:<namespace>:<name>, and (later) an API's
// own, system:api:<group>. Every subject under the reserved "system:"
// prefix is one of Kayra's: a provider's user id with that prefix is
// refused (middleware), so no directory account can pose as one.
package identity

import (
	"regexp"
	"strconv"
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

// FederatedCredential trusts a platform's identity token as one of Kayra's
// own identities (a service account): a GitLab CI job's id_token, a
// GitHub Actions job's, a Kubernetes service account's. The token must
// come from Issuer, one of federation.issuers, carry Audience (Kayra's URL
// when empty) in its aud, and match Subject exactly and every Claims
// value; no wildcard.
type FederatedCredential struct {
	// Name tells it apart: gitlab-main.
	Name string `json:"name" yaml:"name"`
	// Issuer is the token's iss: https://gitlab.example.com.
	Issuer string `json:"issuer" yaml:"issuer"`
	// Subject is its sub, exactly: project_path:infra/compute:ref_type:branch:ref:main.
	Subject string `json:"subject,omitempty" yaml:"subject,omitempty"`
	// Claims are other claims it must carry, each exactly (a boolean as
	// "true"): {"project_path": "infra/compute", "ref_protected": "true"}.
	Claims map[string]string `json:"claims,omitempty" yaml:"claims,omitempty"`
	// Audience is what its aud must hold: Kayra's URL when empty.
	Audience string `json:"audience,omitempty" yaml:"audience,omitempty"`
}

// Matches tells whether claims, a verified token's, are the credential's:
// its sub and every claim, compared as strings.
func (f FederatedCredential) Matches(claims map[string]any) bool {
	if f.Subject != "" && claimString(claims["sub"]) != f.Subject {
		return false
	}
	for k, v := range f.Claims {
		if c, ok := claims[k]; !ok || claimString(c) != v {
			return false
		}
	}
	return f.Subject != "" || len(f.Claims) > 0
}

// claimString is a scalar claim as a string: "true" for a boolean, a
// number's decimal; "" for anything else, which matches no value.
func claimString(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case bool:
		if v {
			return "true"
		}
		return "false"
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}
