package authz

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/infrapi/kayra/internal/config"
)

const fixtureYAML = `
users:
  - id: jdoe
    password: "s3cret"
    attributes:
      email: jdoe@example.com
      name: John Doe
    groups:
      - "cn=sandbox-thetenant-sysadmin,cn=groups,cn=accounts,dc=ipa,dc=global,dc=example,dc=com"
`

func writeFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.yaml")
	if err := os.WriteFile(path, []byte(fixtureYAML), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestDevLocalResolveUser(t *testing.T) {
	a, err := NewDevLocalAuthorizer(&config.LocalAuthzConfig{Path: writeFixture(t)})
	if err != nil {
		t.Fatalf("NewDevLocalAuthorizer: %v", err)
	}

	info, err := a.ResolveUser("jdoe")
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if info.Attributes["email"] != "jdoe@example.com" {
		t.Fatalf("Attributes[email] = %q", info.Attributes["email"])
	}
	if len(info.Groups) != 1 {
		t.Fatalf("Groups = %v, want 1 entry", info.Groups)
	}

	if _, err := a.ResolveUser("nobody"); err != ErrNotFound {
		t.Fatalf("ResolveUser(nobody) = %v, want ErrNotFound", err)
	}
}

func TestDevLocalResolveUserAppliesMemberRegex(t *testing.T) {
	a, err := NewDevLocalAuthorizer(&config.LocalAuthzConfig{
		Path:        writeFixture(t),
		MemberRegex: `^cn=(sandbox-\w+-\w+),cn=groups,cn=accounts,dc=ipa,dc=global,dc=example,dc=com$`,
	})
	if err != nil {
		t.Fatalf("NewDevLocalAuthorizer: %v", err)
	}

	info, err := a.ResolveUser("jdoe")
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if len(info.Groups) != 1 || info.Groups[0] != "sandbox-thetenant-sysadmin" {
		t.Fatalf("Groups = %v, want [sandbox-thetenant-sysadmin] (regex-filtered, parity with the real LDAP backend)", info.Groups)
	}
}

func TestDevLocalLogin(t *testing.T) {
	a, err := NewDevLocalAuthorizer(&config.LocalAuthzConfig{
		Path:        writeFixture(t),
		MemberRegex: `^cn=(sandbox-\w+-\w+),cn=groups,cn=accounts,dc=ipa,dc=global,dc=example,dc=com$`,
	})
	if err != nil {
		t.Fatalf("NewDevLocalAuthorizer: %v", err)
	}

	info, err := a.Login("jdoe", "s3cret")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if info.ID != "jdoe" {
		t.Fatalf("Login ID = %q, want jdoe", info.ID)
	}
	if len(info.Groups) != 1 || info.Groups[0] != "sandbox-thetenant-sysadmin" {
		t.Fatalf("Login Groups = %v, want real resolved groups just like ResolveUser", info.Groups)
	}

	if _, err := a.Login("jdoe", "wrong-password"); err == nil {
		t.Fatalf("Login: want error for wrong password")
	}
	if _, err := a.Login("jdoe", ""); err == nil {
		t.Fatalf("Login: want error for empty password")
	}
	if _, err := a.Login("nobody", "s3cret"); err != ErrNotFound {
		t.Fatalf("Login(nobody) = %v, want ErrNotFound", err)
	}
}
