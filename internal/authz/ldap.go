package authz

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/infrapi/kayra/internal/config"
)

// LDAPAuthorizer resolves users and group members against a real LDAP
// directory, per an authorizations.<name>.ldap config block.
type LDAPAuthorizer struct {
	cfg        *config.LdapConfig
	groupRegex *regexp.Regexp
}

// NewLDAPAuthorizer returns an authorizer for cfg. It does not connect yet:
// a connection is opened per operation, since LDAP lookups are infrequent
// (the result is cached) and this avoids babysitting a long-lived,
// possibly-idle connection.
func NewLDAPAuthorizer(cfg *config.LdapConfig) (*LDAPAuthorizer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("ldap authorizer: config is required")
	}

	re, err := regexp.Compile(cfg.User.Groups.MemberRegex)
	if err != nil {
		return nil, fmt.Errorf("ldap authorizer: compile member_regex: %w", err)
	}

	return &LDAPAuthorizer{cfg: cfg, groupRegex: re}, nil
}

// filterGroups keeps only the raw group DNs matching re, resolving each to
// its first capture group (or the whole match, when re has none).
func filterGroups(raw []string, re *regexp.Regexp) []string {
	var groups []string
	for _, dn := range raw {
		match := re.FindStringSubmatch(dn)
		if match == nil {
			continue
		}
		if len(match) > 1 {
			groups = append(groups, match[1])
		} else {
			groups = append(groups, match[0])
		}
	}
	return groups
}

func (a *LDAPAuthorizer) dial() (*ldap.Conn, error) {
	addr := fmt.Sprintf("%s:%d", a.cfg.Connection.Host, a.cfg.Connection.Port)

	var conn *ldap.Conn
	var err error

	switch a.cfg.Connection.TLS.Encryption {
	case "simple_tls":
		// Verification is on by default: an operator has to set
		// insecure_skip_verify explicitly to turn it off, never the
		// other way around (see LdapTLS).
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: a.cfg.Connection.Host}
		if a.cfg.Connection.TLS.InsecureSkipVerify {
			tlsConfig.InsecureSkipVerify = true
		} else if a.cfg.Connection.TLS.CACert != "" {
			caCert, readErr := os.ReadFile(a.cfg.Connection.TLS.CACert)
			if readErr != nil {
				return nil, fmt.Errorf("ldap: read cacert: %w", readErr)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("ldap: cacert %s has no valid certificates", a.cfg.Connection.TLS.CACert)
			}
			tlsConfig.RootCAs = pool
		}
		conn, err = ldap.DialURL(fmt.Sprintf("ldaps://%s", addr), ldap.DialWithTLSConfig(tlsConfig))
	default:
		conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s", addr))
	}
	if err != nil {
		return nil, fmt.Errorf("ldap: dial %s: %w", addr, err)
	}

	timeout := time.Duration(a.cfg.Connection.Timeout) * time.Second
	if timeout > 0 {
		conn.SetTimeout(timeout)
	}

	if err := conn.Bind(a.cfg.Connection.BindDN, a.cfg.Connection.Password); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ldap: bind as %s: %w", a.cfg.Connection.BindDN, err)
	}

	return conn, nil
}

// normalizeUsername applies the lowercase_usernames and
// allow_username_or_email_login options to a submitted user id.
func (a *LDAPAuthorizer) normalizeUsername(userID string) string {
	username := userID
	if a.cfg.Options.AllowUsernameOrEmailLogin {
		if idx := strings.IndexByte(username, '@'); idx >= 0 {
			username = username[:idx]
		}
	}
	if a.cfg.Options.LowercaseUsernames {
		username = strings.ToLower(username)
	}
	return username
}

// buildFilter wraps idAttr=value together with the always-applied
// base_filter, which the spec gives as a sequence of parenthesised clauses
// without the enclosing (&...).
func buildFilter(idAttr, value, baseFilter string) string {
	if baseFilter == "" {
		return fmt.Sprintf("(%s=%s)", idAttr, ldap.EscapeFilter(value))
	}
	return fmt.Sprintf("(&(%s=%s)%s)", idAttr, ldap.EscapeFilter(value), baseFilter)
}

// shouldRetry reports whether resultCode is one of the configured
// retry_empty_result_with_codes values.
func (a *LDAPAuthorizer) shouldRetry(resultCode int) bool {
	for _, code := range a.cfg.Options.RetryEmptyResultWithCodes {
		if code == resultCode {
			return true
		}
	}
	return false
}

// searchUser locates username's entry over conn, retrying per
// retry_empty_result_with_codes. It returns ErrNotFound when the search
// succeeds but finds nothing.
func (a *LDAPAuthorizer) searchUser(conn *ldap.Conn, username string) (*ldap.Entry, error) {
	filter := buildFilter(a.cfg.User.ID, username, a.cfg.User.BaseFilter)

	attrs := make([]string, 0, len(a.cfg.User.UserAttributes)+1)
	for _, ldapAttr := range a.cfg.User.UserAttributes {
		attrs = append(attrs, ldapAttr)
	}
	attrs = append(attrs, a.cfg.User.Groups.MemberAttribute)

	req := ldap.NewSearchRequest(
		a.cfg.User.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, attrs, nil,
	)

	const maxAttempts = 3
	var result *ldap.SearchResult
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		result, err = conn.Search(req)
		if err == nil && len(result.Entries) > 0 {
			break
		}
		if err != nil {
			if ldapErr, ok := err.(*ldap.Error); ok && a.shouldRetry(int(ldapErr.ResultCode)) {
				continue
			}
			return nil, fmt.Errorf("ldap: search for %s: %w", username, err)
		}
		if len(result.Entries) == 0 {
			break
		}
	}

	if result == nil || len(result.Entries) == 0 {
		return nil, ErrNotFound
	}
	return result.Entries[0], nil
}

// entryToUserInfo maps entry onto UserInfo per the configured
// user_attributes and the group filtering member_regex applies.
func (a *LDAPAuthorizer) entryToUserInfo(userID string, entry *ldap.Entry) UserInfo {
	info := UserInfo{
		ID:         userID,
		Attributes: make(map[string]string, len(a.cfg.User.UserAttributes)),
		Groups:     filterGroups(entry.GetAttributeValues(a.cfg.User.Groups.MemberAttribute), a.groupRegex),
	}
	for localName, ldapAttr := range a.cfg.User.UserAttributes {
		info.Attributes[localName] = entry.GetAttributeValue(ldapAttr)
	}
	return info
}

func (a *LDAPAuthorizer) ResolveUser(userID string) (UserInfo, error) {
	conn, err := a.dial()
	if err != nil {
		return UserInfo{}, err
	}
	defer func() { _ = conn.Close() }()

	entry, err := a.searchUser(conn, a.normalizeUsername(userID))
	if err != nil {
		return UserInfo{}, err
	}

	return a.entryToUserInfo(userID, entry), nil
}

// Login verifies username/password against the directory and, on success,
// returns the same UserInfo ResolveUser would: real LDAP identity and
// group membership, never an operator-asserted claim. It locates the
// user's entry with the service account (the only identity whose
// credentials are in Kayra's own config), then re-binds the same
// connection as that entry's DN with password to verify it — the
// standard "search then bind" LDAP login pattern, since a user's RDN
// value is not guaranteed to be predictable from their username alone.
func (a *LDAPAuthorizer) Login(username, password string) (UserInfo, error) {
	if password == "" {
		return UserInfo{}, fmt.Errorf("ldap: password must not be empty")
	}

	conn, err := a.dial()
	if err != nil {
		return UserInfo{}, err
	}
	defer func() { _ = conn.Close() }()

	normalized := a.normalizeUsername(username)
	entry, err := a.searchUser(conn, normalized)
	if err != nil {
		return UserInfo{}, err
	}

	if err := conn.Bind(entry.DN, password); err != nil {
		return UserInfo{}, fmt.Errorf("ldap: invalid credentials for %s: %w", normalized, err)
	}

	return a.entryToUserInfo(username, entry), nil
}
