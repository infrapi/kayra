// Package config loads and validates the Kayra business configuration: the
// YAML file naming the storage backend, the authentication providers and the
// authorization backends, plus the app: block of shared INFRAPI_APP_*
// bootstrap settings (see AppConfig.ToVariables). It is distinct from
// infrapi/lib's pkg/config, which resolves those same INFRAPI_APP_* keys
// once flattened — Kayra authors them in YAML here instead of a
// separate dotenv file, and hands them off via NewConfigFromMap.
package config

import "gopkg.in/yaml.v3"

// Config is the root of the Kayra YAML configuration file.
type Config struct {
	App               AppConfig                       `yaml:"app"`
	Database          map[string]DatabaseBackend      `yaml:"database"`
	Authentifications map[string]AuthProvider         `yaml:"authentifications"`
	Authorizations    map[string]AuthorizationBackend `yaml:"authorizations"`
	Tokens            TokensConfig                    `yaml:"tokens"`
	Reconciler        ReconcilerConfig                `yaml:"reconciler"`
	Sysadmin          SysadminConfig                  `yaml:"sysadmin"`
}

// AppConfig is the app: block of the Kayra YAML file — the shared
// INFRAPI_APP_* bootstrap settings every infrapi/lib service reads (see
// infrapi/lib's own pkg/config), expressed here in YAML instead of a
// separate dotenv file. ToVariables flattens it into the same
// INFRAPI_APP_* keys libconfig.NewConfigFromMap expects, so this one
// struct is the single place that config is authored; infrapi/lib's own
// validation (required fields, oneof/fqdn/http_url/hostname_port rules —
// see its DefaultConfig) still applies once GetAppConfig resolves it.
type AppConfig struct {
	Name          string `yaml:"name"`
	FQDN          string `yaml:"fqdn"`
	URL           string `yaml:"url"`
	Platform      string `yaml:"platform"`
	Region        string `yaml:"region"`
	Location      string `yaml:"location"`
	ListenType    string `yaml:"listen_type"`
	ListenAddress string `yaml:"listen_address"`
	// APIDomain names this deployment's own API groups — every route
	// internal/rbac and internal/catalog mount, and every Role.Rules
	// entry an operator authors, is "<group>.<APIDomain>" (e.g.
	// "authorization.<APIDomain>"), never a hardcoded domain. Not part
	// of ToVariables: infrapi/lib has no notion of it, it's read
	// directly by apiserver.Build. Empty falls back to "example.com".
	APIDomain string `yaml:"api_domain"`
}

// ToVariables flattens a into the INFRAPI_APP_* keys infrapi/lib's
// libconfig.NewConfigFromMap expects — the same keys NewConfig would
// have read from a dotenv file's INFRAPI_APP_NAME, etc. A field left
// empty here is passed through as an empty string rather than omitted:
// libconfig.Variables.GetString treats an absent and an empty value
// identically (falling back to that key's own default, when it has
// one), so there's no reason to distinguish them here.
func (a AppConfig) ToVariables() map[string]string {
	return map[string]string{
		"INFRAPI_APP_NAME":           a.Name,
		"INFRAPI_APP_FQDN":           a.FQDN,
		"INFRAPI_APP_URL":            a.URL,
		"INFRAPI_APP_PLATFORM":       a.Platform,
		"INFRAPI_APP_REGION":         a.Region,
		"INFRAPI_APP_LOCATION":       a.Location,
		"INFRAPI_APP_LISTEN_TYPE":    a.ListenType,
		"INFRAPI_APP_LISTEN_ADDRESS": a.ListenAddress,
	}
}

// DatabaseBackend is one named entry under database:. Exactly one entry in
// the map must be populated with either Etcd or Local, never both.
type DatabaseBackend struct {
	Etcd  *EtcdConfig  `yaml:"etcd"`
	Local *LocalConfig `yaml:"local"`
}

// EtcdConfig describes a real etcd cluster backend.
type EtcdConfig struct {
	Host    []string   `yaml:"host"`
	Prefix  string     `yaml:"prefix"`
	Timeout int        `yaml:"timeout"`
	TLS     *TLSConfig `yaml:"tls"`
}

// TLSConfig describes the TLS/mTLS material used to reach etcd over https.
type TLSConfig struct {
	Verify bool   `yaml:"verify"`
	CACert string `yaml:"cacert"`
	Key    string `yaml:"key"`
	Cert   string `yaml:"cert"`
}

// LocalConfig simulates etcd with a directory of files on disk, for dev use.
type LocalConfig struct {
	Path   string `yaml:"path"`
	Prefix string `yaml:"prefix"`
}

// AuthProvider is one named entry under authentifications:. Remote is an
// OIDC-discovery-backed provider (okta, gitlab, console, ...); Local is a
// list of signing keys this Kayra instance verifies and may itself issue
// with (the "self" provider in the spec).
type AuthProvider struct {
	Authorization string            `yaml:"authorization"`
	Remote        *RemoteAuthConfig `yaml:"remote"`
	Local         []LocalSigningKey `yaml:"local"`
}

// RemoteAuthConfig points at an external OIDC provider's discovery document.
type RemoteAuthConfig struct {
	Enabled bool         `yaml:"enabled"`
	URL     string       `yaml:"url"`
	UserID  UserIDConfig `yaml:"user_id"`
	// Proxy, when set, is the HTTP(S) proxy every outbound call this
	// provider makes (discovery, JWKS, userinfo, and OAuth2's own
	// authorize/token calls) is routed through — independently of any
	// other provider, and independently of the process-wide
	// HTTP_PROXY/HTTPS_PROXY/NO_PROXY env vars Go's default transport
	// already honors when this is unset. One provider reachable only
	// through a corporate egress proxy and another reachable directly
	// is a real shape, not a hypothetical.
	Proxy string `yaml:"proxy"`
	// OAuth2, when set, lets `kayra-cli login` authenticate against
	// this provider via a real browser-based Authorization Code + PKCE
	// flow, brokered through this server (see internal/oauth2broker and
	// internal/oauth2login) instead of a username/password bind — the
	// same flow `oc login` runs against OpenShift's own /oauth/authorize.
	OAuth2 *OAuth2LoginConfig `yaml:"oauth2"`
}

// OAuth2LoginConfig is a remote provider's own OAuth2 client
// registration, used only to broker `kayra-cli login` (see
// internal/oauth2broker) — never by the API server's own token
// verification, which only ever checks tokens already issued by the
// provider, not requests them.
type OAuth2LoginConfig struct {
	// ClientID is this CLI's client_id in the provider's own OAuth2 app
	// registration — a public client (PKCE replaces the need for a
	// client_secret, exactly like oc/kubectl's own OIDC plugins).
	ClientID string `yaml:"client_id"`
	// Scopes requested from the provider; empty defaults to
	// oauth2login.DefaultScopes ("openid", "profile", "email").
	Scopes []string `yaml:"scopes"`
}

// UserIDConfig says how to pull the user id out of a validated token.
type UserIDConfig struct {
	// From is "token" (read Field from the token claims) or
	// "userinfo_endpoint" (call the provider's userinfo endpoint and read
	// Field from the JSON response).
	From string `yaml:"from"`
	// Field is the claim or JSON field holding the user id.
	Field string `yaml:"field"`
	// Filter is an optional regexp with one capture group; when set, the
	// user id is the first submatch instead of the raw field value.
	Filter string `yaml:"filter"`
}

// LocalSigningKey is one RSA signing key this Kayra instance trusts for
// self-issued tokens, keyed by Kid.
type LocalSigningKey struct {
	Enabled   bool     `yaml:"enabled"`
	Algorithm string   `yaml:"algorithm"`
	Audiences []string `yaml:"audiences"`
	Expiry    int      `yaml:"expiry"`
	Issuer    bool     `yaml:"issuer"`
	Kid       string   `yaml:"kid"`
	// Secret is a PEM-encoded RSA private key.
	Secret string `yaml:"secret"`
}

// AuthorizationBackend is one named entry under authorizations:. Exactly one
// of Ldap, Local or Claims must be set.
type AuthorizationBackend struct {
	Ldap   *LdapConfig        `yaml:"ldap"`
	Local  *LocalAuthzConfig  `yaml:"local"`
	Claims *ClaimsAuthzConfig `yaml:"claims"`
}

// ClaimsAuthzConfig resolves a caller's groups and attributes directly
// from their already-verified token claims or userinfo response —
// whichever authentifications.<name>.remote provider names this backend
// — instead of a separate directory lookup. For a provider (Okta, say)
// whose own token/userinfo already carries real group membership (e.g.
// Okta's own "MemberOf"), this is enough on its own: no ldap entry, no
// second network call, since the data is already in hand from
// verifying the token.
//
// From/GroupsField/GroupsFilter mirror AuthProvider.Remote.UserID's own
// From/Field/Filter exactly (see authn.ResolveUserID) — same two
// sources ("token" or "userinfo_endpoint"), just applied to a list
// claim instead of a scalar one: GroupsFilter, when set, is applied
// independently to every element exactly like
// authorizations.<name>.ldap.user.groups.member_regex does to a real
// memberOf value — an element that doesn't match is dropped, one that
// does contributes its first capture group (or the whole match) to the
// result. UserAttributes is the same local_name -> field mapping
// authorizations.<name>.ldap.user.user_attributes uses, just read from
// the same token/userinfo source instead of an LDAP entry.
//
// Deliberately cannot back a PasswordAuthenticator (there is no
// username/password to check here, only an already-issued token) and
// cannot be re-resolved later from a bare user id alone (there is no
// live session to re-query) — see PatRecord.SnapshotGroups/
// SnapshotAttributes for how personal access tokens cope with that.
type ClaimsAuthzConfig struct {
	From           string            `yaml:"from"`
	GroupsField    string            `yaml:"groups_field"`
	GroupsFilter   string            `yaml:"groups_filter"`
	UserAttributes map[string]string `yaml:"user_attributes"`
}

// LocalAuthzConfig points at a fixture file simulating an LDAP directory, for
// dev/test use without a real LDAP server.
type LocalAuthzConfig struct {
	Path string `yaml:"path"`
	// MemberRegex, when set, is applied to every fixture user's Groups
	// list exactly like authorizations.<name>.ldap.user.groups.member_regex
	// does to a real memberOf list — same drop-non-matches,
	// keep-first-capture-group semantics — so a fixture can mirror raw
	// LDAP-style DNs and exercise the same filtering in dev. Optional:
	// leave unset to author the fixture's Groups as the final resolved
	// names directly.
	MemberRegex string `yaml:"member_regex"`
}

// LdapConfig describes a real LDAP authorization backend.
type LdapConfig struct {
	Enabled    bool           `yaml:"enabled"`
	Connection LdapConnection `yaml:"connection"`
	Options    LdapOptions    `yaml:"options"`
	User       LdapUserConfig `yaml:"user"`
}

// LdapConnection is how Kayra reaches and binds to the LDAP server.
type LdapConnection struct {
	Host     string  `yaml:"host"`
	Port     int     `yaml:"port"`
	BindDN   string  `yaml:"bind_dn"`
	Password string  `yaml:"password"`
	Timeout  int     `yaml:"timeout"`
	TLS      LdapTLS `yaml:"tls"`
}

// LdapTLS describes the encryption used to reach the LDAP server.
// Certificate verification is on by default (against the system CA pool,
// or CACert when set) once Encryption picks a TLS mode: an operator has
// to opt into InsecureSkipVerify explicitly, never the other way around
// — omitting a field must never silently downgrade a TLS connection to
// an unauthenticated one.
type LdapTLS struct {
	CACert             string `yaml:"cacert"`
	Encryption         string `yaml:"encryption"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

// LdapOptions tunes LDAP query behaviour.
type LdapOptions struct {
	LowercaseUsernames        bool   `yaml:"lowercase_usernames"`
	RetryEmptyResultWithCodes []int  `yaml:"retry_empty_result_with_codes"`
	AllowUsernameOrEmailLogin bool   `yaml:"allow_username_or_email_login"`
	CacheTTL                  string `yaml:"cache_ttl"`
}

// LdapUserConfig describes how users and their groups are found and mapped.
type LdapUserConfig struct {
	ID             string            `yaml:"id"`
	Base           string            `yaml:"base"`
	BaseFilter     string            `yaml:"base_filter"`
	UserAttributes map[string]string `yaml:"user_attributes"`
	Groups         LdapGroupsConfig  `yaml:"groups"`
}

// LdapGroupsConfig describes how a user's group membership is resolved.
type LdapGroupsConfig struct {
	// MemberAttribute is the multi-valued attribute on the user entry
	// listing the DNs of every group it belongs to (e.g. "memberof").
	MemberAttribute string `yaml:"member_attribute"`
	// MemberRegex filters that raw DN list down to the groups Kayra
	// cares about: a DN that does not match is dropped entirely, and one
	// that does contributes its first capture group (or the whole match,
	// when the regex has no capture group) as the resolved group name.
	MemberRegex string `yaml:"member_regex"`
}

// TokensConfig configures token issuance.
type TokensConfig struct {
	Pat PatConfig `yaml:"pat"`
}

// PatConfig configures the keypair used to encrypt personal access tokens at
// rest. When PrivateKeyPath/PublicKeyPath are empty, a keypair is generated
// on first start and persisted under the store at the default location.
type PatConfig struct {
	PrivateKeyPath string `yaml:"private_key_path"`
	PublicKeyPath  string `yaml:"public_key_path"`
}

// ReconcilerConfig configures `kayra reconciler` (catalog.Reconciler).
type ReconcilerConfig struct {
	// MaxConcurrentReconciles caps how many reconcile/activate operations
	// Reconciler runs at once — the goroutine pool size behind every
	// namespace/subscription activation and every api-registration
	// -triggered subscription reconcile. Zero (the key absent, the
	// typical case) falls back to catalog.DefaultMaxConcurrentReconciles.
	MaxConcurrentReconciles int `yaml:"max_concurrent_reconciles"`
	// DefaultMode is used when an ApiRegistration's own Mode is unset:
	// without this, a registration whose owner never bothered to set
	// mode: fails reconcile forever (see catalog.Reconciler.reconcile),
	// rather than just assuming the deployment's usual default. Empty
	// (the typical case) keeps that failing behavior — an explicit
	// ApiRegistration.Mode is still always honored over this when the
	// registration has one.
	DefaultMode string `yaml:"default_mode"`
	// Mode names the HTTP step pipeline reconcile runs for an api
	// registration whose Mode (after DefaultMode falls back) resolves to
	// that key — "trigger" and "api" in every example, but any name
	// works, since this is just a map. A mode with no entry here keeps
	// reconcile's placeholder log-only behavior; one that does gets its
	// steps run for real, in order, each one's success or failure
	// described on ReconcileStep.
	Mode map[string][]ReconcileStep `yaml:"mode"`
}

// SysadminConfig configures middleware.SysadminGate — the privileged
// group(s) a caller's resolved groups must intersect to reach the
// cluster-bootstrap endpoints (rbac's cluster routes, catalog's api
// registration and namespace-collection routes). Authored directly in config rather
// than derived from a template, so a deployment can name real
// LDAP/IdP groups it already has instead of being locked into a
// single "$platform-core-sysadmin" convention.
type SysadminConfig struct {
	// Groups is the list of group names SysadminGate accepts — a
	// caller passes if their resolved Groups contains any one of
	// these. Empty (the typical case, and the default before this was
	// configurable) falls back to a single group:
	// middleware.SysadminGroupFor(platform), e.g. "sandbox-core-sysadmin".
	Groups []string `yaml:"groups"`
}

// ReconcileStep is one HTTP call in a mode's pipeline. Endpoint, every
// string value reachable inside Data (however deeply nested — Data's own
// values, object fields, array elements, any combination), and every
// Headers value renders as a Go text/template first, against a struct
// exposing ".Subscription" (Api, Namespace, Platform, Region,
// CurrentSyncID, ExpectedSyncID — all strings) and ".Previous.Outputs"
// (the preceding step's own Outputs, keyed exactly as that step declared
// them; empty for the first step).
//
// Async decides what "this step succeeded" even means:
//
//   - Async: false (the default) — the call is made and awaited up to
//     Timeout; a non-2xx response, a timeout, or a transport error fails
//     the step, which aborts the whole pipeline (reconcile fails, and
//     Reconciler never advances the subscription's CurrentSyncID — see
//     Reconciler.ensureReconciled).
//   - Async: true — the call is made but only waited on briefly (see
//     catalog.AsyncStepAckTimeout); whatever happens — success, failure,
//     or no response in time — is logged and then ignored: the pipeline
//     always moves on to the next step (or, with none left, the whole
//     pipeline succeeds) regardless. Outputs are still extracted from
//     whatever response did arrive in time, best-effort. Wait (below) is
//     ignored on an async step: fire-and-forget and "block until a
//     terminal state" are contradictory.
type ReconcileStep struct {
	Method   string `yaml:"method"`
	Endpoint string `yaml:"endpoint"`
	// Data becomes the request body, JSON-encoded after templating —
	// any shape YAML can express (a flat map, or arbitrarily nested
	// objects/arrays, e.g. GitLab's pipeline-create "variables: [{key,
	// value}, ...]"), not just a flat string map.
	Data    map[string]any         `yaml:"data"`
	Headers map[string]HeaderValue `yaml:"headers"`
	// Timeout is a Go duration string ("3600s", "1h"): how long a
	// non-async step waits for its response before failing. An async
	// step is capped at catalog.AsyncStepAckTimeout regardless of what's
	// set here.
	Timeout string `yaml:"timeout"`
	Async   bool   `yaml:"async"`
	// Outputs names values to pull out of the JSON response body, keyed
	// by whatever name the next step should know them by, valued by a
	// simple dot path into the body (e.g. ".pipeline_id", or
	// ".items[0].id" — not a full JSONPath implementation: just object
	// field and array index traversal).
	Outputs map[string]string `yaml:"outputs"`
	// Wait turns this step from "call once, status 2xx is success" into
	// "call repeatedly until every condition's own Key value lands in its
	// Successes or Failures" — see WaitCondition. Ignored on an async
	// step. Every condition must resolve to Successes for the step to
	// succeed; any single one resolving to Failures fails the step
	// immediately. Re-checked every catalog.WaitPollInterval until one of
	// those happens or Timeout elapses (a timeout is a failure).
	Wait []WaitCondition `yaml:"wait"`
}

// WaitCondition is one field ReconcileStep.Wait polls a step's own
// response for: Key is the same dot-path format Outputs uses (e.g.
// ".status"). Its current value landing in Successes resolves this
// condition done; landing in Failures fails the whole step immediately,
// without waiting for any other condition; landing in neither — or the
// response not parsing as JSON, or Key not resolving at all — means
// "not yet", so the step keeps polling.
type WaitCondition struct {
	Key       string   `yaml:"key"`
	Successes []string `yaml:"successes"`
	Failures  []string `yaml:"failures"`
}

// HeaderValue is one Headers entry: either a plain string (used as the
// header value verbatim, after templating), or a {type, value} pair
// rendered as "<type> <value>" (e.g. {type: Bearer, value: "tok"} ->
// "Bearer tok") — so an Authorization header never has to spell out the
// scheme inline.
type HeaderValue struct {
	Raw   string
	Type  string
	Value string
}

// UnmarshalYAML accepts either a bare scalar string or a {type, value}
// mapping for one HeaderValue.
func (h *HeaderValue) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		return value.Decode(&h.Raw)
	}
	var typed struct {
		Type  string `yaml:"type"`
		Value string `yaml:"value"`
	}
	if err := value.Decode(&typed); err != nil {
		return err
	}
	h.Type, h.Value = typed.Type, typed.Value
	return nil
}

// Render returns this header's final value: the raw string as-is, or
// "<type> <value>" for a typed one.
func (h HeaderValue) Render() string {
	if h.Type == "" {
		return h.Raw
	}
	return h.Type + " " + h.Value
}
