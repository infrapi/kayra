package authz

import (
	"regexp"
	"testing"

	"github.com/infrapi/kayra/internal/config"
)

func validLdapConfig() config.LdapConfig {
	return config.LdapConfig{
		Connection: config.LdapConnection{Host: "ldap.example.com", Port: 636},
		User: config.LdapUserConfig{
			ID: "uid",
			Groups: config.LdapGroupsConfig{
				MemberAttribute: "memberof",
				MemberRegex:     `^cn=sandbox-(\w+-\w+),cn=groups.*$`,
			},
		},
	}
}

func TestFilterGroupsExtractsCaptureGroup(t *testing.T) {
	re := regexp.MustCompile(`^cn=sandbox-(\w+-\w+),cn=groups,cn=accounts,dc=ipa,dc=global,dc=example,dc=com$`)

	raw := []string{
		"cn=sandbox-thetenant-sysadmin,cn=groups,cn=accounts,dc=ipa,dc=global,dc=example,dc=com",
		"cn=sandbox-myns-apps,cn=groups,cn=accounts,dc=ipa,dc=global,dc=example,dc=com",
		"cn=some-other-group,cn=groups,cn=accounts,dc=ipa,dc=global,dc=example,dc=com",
		"cn=posix-users,cn=groups,cn=accounts,dc=ipa,dc=global,dc=example,dc=com",
	}

	got := filterGroups(raw, re)

	want := []string{"thetenant-sysadmin", "myns-apps"}
	if len(got) != len(want) {
		t.Fatalf("filterGroups = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("filterGroups[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestFilterGroupsNoMatches(t *testing.T) {
	re := regexp.MustCompile(`^cn=sandbox-(\w+-\w+),cn=groups.*$`)

	raw := []string{"cn=posix-users,cn=groups,cn=accounts,dc=example,dc=com"}

	got := filterGroups(raw, re)
	if len(got) != 0 {
		t.Fatalf("filterGroups = %v, want empty", got)
	}
}

func TestFilterGroupsNoCaptureGroupReturnsWholeMatch(t *testing.T) {
	re := regexp.MustCompile(`^cn=sandbox-\w+-\w+,cn=groups.*$`)

	raw := []string{"cn=sandbox-thetenant-sysadmin,cn=groups,cn=accounts,dc=example,dc=com"}

	got := filterGroups(raw, re)
	if len(got) != 1 || got[0] != raw[0] {
		t.Fatalf("filterGroups = %v, want [%q]", got, raw[0])
	}
}

func TestNewLDAPAuthorizerRejectsBadRegex(t *testing.T) {
	cfg := validLdapConfig()
	cfg.User.Groups.MemberRegex = "(unclosed"

	if _, err := NewLDAPAuthorizer(&cfg); err == nil {
		t.Fatalf("NewLDAPAuthorizer: want error for invalid member_regex")
	}
}
