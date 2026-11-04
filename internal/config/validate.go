package config

import (
	"fmt"
	neturl "net/url"
	"regexp"
	"strings"
	"time"
)

// Validate checks structural invariants the YAML schema alone can't express:
// exactly one backend chosen per union field, and every cross-reference
// between authentifications and authorizations resolves.
func (c *Config) Validate() error {
	if _, _, err := c.ActiveDatabase(); err != nil {
		return err
	}
	for name, db := range c.Database {
		if err := db.validate(name); err != nil {
			return err
		}
	}

	if len(c.Authorizations) == 0 {
		return fmt.Errorf("authorizations: at least one entry required")
	}
	for name, authz := range c.Authorizations {
		if err := authz.validate(name); err != nil {
			return err
		}
	}

	if len(c.Authentifications) == 0 {
		return fmt.Errorf("authentifications: at least one entry required")
	}
	for name, provider := range c.Authentifications {
		if err := provider.validate(name, c.Authorizations); err != nil {
			return err
		}
	}

	if c.Reconciler.MaxConcurrentReconciles < 0 {
		return fmt.Errorf("reconciler.max_concurrent_reconciles: must not be negative")
	}
	// DefaultMode is a free-form key into Mode, same as a Stack's own
	// mode: field — "trigger" and "api" in every example, but nothing
	// hardcoded requires either name, so there is nothing to whitelist
	// here beyond what Mode's own per-step validation already covers.
	for mode, steps := range c.Reconciler.Mode {
		for i, step := range steps {
			if err := step.validate(mode, i); err != nil {
				return err
			}
		}
	}

	return nil
}

func (d DatabaseBackend) validate(name string) error {
	switch {
	case d.Etcd != nil && d.Local != nil:
		return fmt.Errorf("database.%s: etcd and local are mutually exclusive", name)
	case d.Etcd == nil && d.Local == nil:
		return fmt.Errorf("database.%s: one of etcd or local is required", name)
	case d.Etcd != nil:
		if len(d.Etcd.Host) == 0 {
			return fmt.Errorf("database.%s.etcd: host is required", name)
		}
		if d.Etcd.Prefix == "" {
			return fmt.Errorf("database.%s.etcd: prefix is required", name)
		}
	case d.Local != nil:
		if d.Local.Path == "" {
			return fmt.Errorf("database.%s.local: path is required", name)
		}
	}
	return nil
}

func (a AuthorizationBackend) validate(name string) error {
	set := 0
	for _, v := range []bool{a.Ldap != nil, a.Local != nil, a.Claims != nil} {
		if v {
			set++
		}
	}
	switch {
	case set > 1:
		return fmt.Errorf("authorizations.%s: ldap, local and claims are mutually exclusive", name)
	case set == 0:
		return fmt.Errorf("authorizations.%s: one of ldap, local or claims is required", name)
	case a.Ldap != nil:
		if a.Ldap.Connection.Host == "" {
			return fmt.Errorf("authorizations.%s.ldap.connection: host is required", name)
		}
		if a.Ldap.User.ID == "" {
			return fmt.Errorf("authorizations.%s.ldap.user: id is required", name)
		}
		if a.Ldap.User.Groups.MemberRegex == "" {
			return fmt.Errorf("authorizations.%s.ldap.user.groups: member_regex is required", name)
		}
		if _, err := regexp.Compile(a.Ldap.User.Groups.MemberRegex); err != nil {
			return fmt.Errorf("authorizations.%s.ldap.user.groups.member_regex: %w", name, err)
		}
	case a.Local != nil:
		if a.Local.Path == "" {
			return fmt.Errorf("authorizations.%s.local: path is required", name)
		}
		if a.Local.MemberRegex != "" {
			if _, err := regexp.Compile(a.Local.MemberRegex); err != nil {
				return fmt.Errorf("authorizations.%s.local.member_regex: %w", name, err)
			}
		}
	case a.Claims != nil:
		switch a.Claims.From {
		case "token", "userinfo_endpoint":
		default:
			return fmt.Errorf("authorizations.%s.claims.from: must be %q or %q, got %q", name, "token", "userinfo_endpoint", a.Claims.From)
		}
		if a.Claims.GroupsField == "" {
			return fmt.Errorf("authorizations.%s.claims: groups_field is required", name)
		}
		if a.Claims.GroupsFilter != "" {
			if _, err := regexp.Compile(a.Claims.GroupsFilter); err != nil {
				return fmt.Errorf("authorizations.%s.claims.groups_filter: %w", name, err)
			}
		}
	}
	return nil
}

func (p AuthProvider) validate(name string, authz map[string]AuthorizationBackend) error {
	if p.Authorization == "" {
		return fmt.Errorf("authentifications.%s: authorization is required", name)
	}
	authzCfg, ok := authz[p.Authorization]
	if !ok {
		return fmt.Errorf("authentifications.%s: authorization %q is not defined under authorizations", name, p.Authorization)
	}
	// A claims backend with from: userinfo_endpoint reads the issuing
	// provider's own userinfo response — meaningless for a local
	// (self-signed) provider, which has no remote session to query at
	// all. Catch it here, at load time, instead of letting it reach
	// oidc.FetchDiscouvery("") as a confusing empty-URL HTTP error.
	if authzCfg.Claims != nil && authzCfg.Claims.From == "userinfo_endpoint" && p.Remote == nil {
		return fmt.Errorf("authentifications.%s: authorization %q resolves claims from userinfo_endpoint, which requires remote (a local/self-signed provider has no userinfo endpoint to call — use claims.from: token instead if %[1]s is local)", name, p.Authorization)
	}

	switch {
	case p.Remote != nil && len(p.Local) > 0:
		return fmt.Errorf("authentifications.%s: remote and local are mutually exclusive", name)
	case p.Remote == nil && len(p.Local) == 0:
		return fmt.Errorf("authentifications.%s: one of remote or local is required", name)
	case p.Remote != nil:
		if p.Remote.URL == "" {
			return fmt.Errorf("authentifications.%s.remote: url is required", name)
		}
		switch p.Remote.UserID.From {
		case "token", "userinfo_endpoint":
		default:
			return fmt.Errorf("authentifications.%s.remote.user_id.from: must be %q or %q", name, "token", "userinfo_endpoint")
		}
		if p.Remote.UserID.Field == "" {
			return fmt.Errorf("authentifications.%s.remote.user_id: field is required", name)
		}
		if p.Remote.Proxy != "" {
			if _, err := neturl.Parse(p.Remote.Proxy); err != nil {
				return fmt.Errorf("authentifications.%s.remote.proxy: %w", name, err)
			}
		}
		if p.Remote.OAuth2 != nil && p.Remote.OAuth2.ClientID == "" {
			return fmt.Errorf("authentifications.%s.remote.oauth2: client_id is required", name)
		}
	case len(p.Local) > 0:
		for i, key := range p.Local {
			if key.Kid == "" {
				return fmt.Errorf("authentifications.%s.local[%d]: kid is required", name, i)
			}
			if key.Secret == "" {
				return fmt.Errorf("authentifications.%s.local[%d]: secret is required", name, i)
			}
		}
	}
	return nil
}

var validStepMethods = map[string]bool{
	"get": true, "post": true, "put": true, "patch": true, "delete": true,
}

func (s ReconcileStep) validate(mode string, index int) error {
	prefix := fmt.Sprintf("reconciler.mode.%s[%d]", mode, index)
	if !validStepMethods[strings.ToLower(s.Method)] {
		return fmt.Errorf("%s.method: must be one of get, post, put, patch, delete, got %q", prefix, s.Method)
	}
	if s.Endpoint == "" {
		return fmt.Errorf("%s.endpoint: is required", prefix)
	}
	if s.Timeout == "" {
		return fmt.Errorf("%s.timeout: is required", prefix)
	}
	if _, err := time.ParseDuration(s.Timeout); err != nil {
		return fmt.Errorf("%s.timeout: %w", prefix, err)
	}
	for i, cond := range s.Wait {
		if cond.Key == "" {
			return fmt.Errorf("%s.wait[%d].key: is required", prefix, i)
		}
	}
	return nil
}
