package authz

import (
	"crypto/subtle"
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"

	"github.com/infrapi/kayra/internal/config"
)

// DevLocalFixture is the on-disk shape of an authorizations.<name>.local
// fixture file: a stand-in for an LDAP directory, for dev/test use.
type DevLocalFixture struct {
	Users []DevLocalUser `yaml:"users"`
}

// DevLocalUser mirrors one LDAP user entry. Password is only consulted by
// Login, dev/test plaintext — never meant for anything real.
type DevLocalUser struct {
	ID         string            `yaml:"id"`
	Password   string            `yaml:"password"`
	Attributes map[string]string `yaml:"attributes"`
	Groups     []string          `yaml:"groups"`
}

// DevLocalAuthorizer implements Authorizer by reading a DevLocalFixture from
// disk, for the "authorizations.dev.local" backend the spec calls out for
// testing without a real LDAP server.
type DevLocalAuthorizer struct {
	fixture    DevLocalFixture
	groupRegex *regexp.Regexp // nil when member_regex is unset: no filtering
}

// NewDevLocalAuthorizer loads the fixture at path. cfg.MemberRegex, when
// set, is applied to every user's fixture Groups exactly like the real LDAP
// backend's member_regex — same drop-non-matches, keep-first-capture-group
// semantics — so a fixture authored with raw DN-shaped strings exercises
// the same filtering a real directory would.
func NewDevLocalAuthorizer(cfg *config.LocalAuthzConfig) (*DevLocalAuthorizer, error) {
	data, err := os.ReadFile(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("devlocal: read fixture %s: %w", cfg.Path, err)
	}

	var fixture DevLocalFixture
	if err := yaml.Unmarshal(data, &fixture); err != nil {
		return nil, fmt.Errorf("devlocal: parse fixture %s: %w", cfg.Path, err)
	}

	var re *regexp.Regexp
	if cfg.MemberRegex != "" {
		re, err = regexp.Compile(cfg.MemberRegex)
		if err != nil {
			return nil, fmt.Errorf("devlocal: compile member_regex: %w", err)
		}
	}

	return &DevLocalAuthorizer{fixture: fixture, groupRegex: re}, nil
}

func (a *DevLocalAuthorizer) findUser(userID string) (DevLocalUser, bool) {
	for _, u := range a.fixture.Users {
		if u.ID == userID {
			return u, true
		}
	}
	return DevLocalUser{}, false
}

func (a *DevLocalAuthorizer) toUserInfo(u DevLocalUser) UserInfo {
	groups := u.Groups
	if a.groupRegex != nil {
		groups = filterGroups(groups, a.groupRegex)
	}
	return UserInfo{ID: u.ID, Attributes: u.Attributes, Groups: groups}
}

func (a *DevLocalAuthorizer) ResolveUser(userID string) (UserInfo, error) {
	u, ok := a.findUser(userID)
	if !ok {
		return UserInfo{}, ErrNotFound
	}
	return a.toUserInfo(u), nil
}

// Login checks password against the fixture's plaintext password field —
// dev/test only, standing in for the real LDAP backend's bind-based check.
func (a *DevLocalAuthorizer) Login(username, password string) (UserInfo, error) {
	u, ok := a.findUser(username)
	if !ok {
		return UserInfo{}, ErrNotFound
	}
	if password == "" || subtle.ConstantTimeCompare([]byte(u.Password), []byte(password)) != 1 {
		return UserInfo{}, fmt.Errorf("devlocal: invalid credentials for %s", username)
	}
	return a.toUserInfo(u), nil
}
