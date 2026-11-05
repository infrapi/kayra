package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kayra.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

const validConfig = `
database:
  dev:
    local:
      path: /tmp/kayra-db

authentifications:
  okta:
    authorization: idm
    remote:
      enabled: true
      url: https://example.okta.com/.well-known/openid-configuration
      user_id:
        from: token
        field: sub
        filter: '^([^@]+)@'
  self:
    authorization: dev
    local:
      - enabled: true
        algorithm: RS512
        audiences: []
        expiry: 3600
        issuer: true
        kid: "key-1"
        secret: "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----"

authorizations:
  idm:
    ldap:
      enabled: true
      connection:
        host: ldap.example.com
        port: 636
      user:
        id: uid
        groups:
          member_attribute: memberof
          member_regex: '^cn=sandbox-(\w+-\w+),cn=groups,.*$'
  dev:
    local:
      path: /tmp/kayra-users.yaml
`

// TestLoadParsesAppBlock confirms the app: block round-trips into
// Config.App, and that ToVariables flattens it into the exact
// INFRAPI_APP_* keys infrapi/lib's libconfig.NewConfigFromMap expects
// (see getting-started.md's former dotenv file, now folded into this
// same YAML config instead).
func TestLoadParsesAppBlock(t *testing.T) {
	appConfig := `
app:
  name: "auth"
  fqdn: "localhost.local"
  url: "http://localhost:8080"
  platform: "sandbox"
  region: "eu-west-1"
  location: "dc1"
  listen_type: "tcp"
  listen_address: "0.0.0.0:8080"
`
	path := writeConfig(t, appConfig+validConfig)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	want := AppConfig{
		Name: "auth", FQDN: "localhost.local", URL: "http://localhost:8080",
		Platform: "sandbox", Region: "eu-west-1", Location: "dc1",
		ListenType: "tcp", ListenAddress: "0.0.0.0:8080",
	}
	if cfg.App != want {
		t.Fatalf("cfg.App = %+v, want %+v", cfg.App, want)
	}

	vars := cfg.App.ToVariables()
	wantVars := map[string]string{
		"INFRAPI_APP_NAME":           "auth",
		"INFRAPI_APP_FQDN":           "localhost.local",
		"INFRAPI_APP_URL":            "http://localhost:8080",
		"INFRAPI_APP_PLATFORM":       "sandbox",
		"INFRAPI_APP_REGION":         "eu-west-1",
		"INFRAPI_APP_LOCATION":       "dc1",
		"INFRAPI_APP_LISTEN_TYPE":    "tcp",
		"INFRAPI_APP_LISTEN_ADDRESS": "0.0.0.0:8080",
	}
	if len(vars) != len(wantVars) {
		t.Fatalf("ToVariables() = %v, want %v", vars, wantVars)
	}
	for k, want := range wantVars {
		if got := vars[k]; got != want {
			t.Fatalf("ToVariables()[%q] = %q, want %q", k, got, want)
		}
	}
}

func TestLoadValid(t *testing.T) {
	path := writeConfig(t, validConfig)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	name, backend, err := cfg.ActiveDatabase()
	if err != nil {
		t.Fatalf("ActiveDatabase: %v", err)
	}
	if name != "dev" {
		t.Fatalf("ActiveDatabase name = %q, want dev", name)
	}
	if backend.Local == nil || backend.Local.Path != "/tmp/kayra-db" {
		t.Fatalf("ActiveDatabase backend = %+v", backend)
	}

	if len(cfg.Authentifications) != 2 {
		t.Fatalf("Authentifications = %d entries, want 2", len(cfg.Authentifications))
	}
}

func TestLoadRejectsTwoDatabases(t *testing.T) {
	bad := `
database:
  dev:
    local:
      path: /tmp/kayra-db
  main:
    local:
      path: /tmp/other
authentifications:
  self:
    authorization: dev
    local:
      - enabled: true
        algorithm: RS512
        kid: "key-1"
        secret: "fake"
authorizations:
  dev:
    local:
      path: /tmp/kayra-users.yaml
`
	path := writeConfig(t, bad)

	if _, err := Load(path); err == nil {
		t.Fatalf("Load: want error for two database entries")
	}
}

func TestLoadRejectsUnknownAuthorization(t *testing.T) {
	bad := `
database:
  dev:
    local:
      path: /tmp/kayra-db
authentifications:
  okta:
    authorization: missing
    remote:
      enabled: true
      url: https://example.okta.com/.well-known/openid-configuration
      user_id:
        from: token
        field: sub
authorizations:
  idm:
    ldap:
      enabled: true
      connection:
        host: ldap.example.com
      user:
        id: uid
`
	path := writeConfig(t, bad)
	if _, err := Load(path); err == nil {
		t.Fatalf("Load: want error for unknown authorization reference")
	}
}

func TestLoadRejectsMissingMemberRegex(t *testing.T) {
	bad := `
database:
  dev:
    local:
      path: /tmp/kayra-db
authentifications:
  okta:
    authorization: idm
    remote:
      enabled: true
      url: https://example.okta.com/.well-known/openid-configuration
      user_id:
        from: token
        field: sub
authorizations:
  idm:
    ldap:
      enabled: true
      connection:
        host: ldap.example.com
      user:
        id: uid
        groups:
          member_attribute: memberof
`
	path := writeConfig(t, bad)
	if _, err := Load(path); err == nil {
		t.Fatalf("Load: want error for missing member_regex")
	}
}

func TestLoadRejectsInvalidMemberRegex(t *testing.T) {
	bad := `
database:
  dev:
    local:
      path: /tmp/kayra-db
authentifications:
  okta:
    authorization: idm
    remote:
      enabled: true
      url: https://example.okta.com/.well-known/openid-configuration
      user_id:
        from: token
        field: sub
authorizations:
  idm:
    ldap:
      enabled: true
      connection:
        host: ldap.example.com
      user:
        id: uid
        groups:
          member_attribute: memberof
          member_regex: "(unclosed"
`
	path := writeConfig(t, bad)
	if _, err := Load(path); err == nil {
		t.Fatalf("Load: want error for invalid member_regex")
	}
}

func TestLoadReconcilerDefaultsToZero(t *testing.T) {
	path := writeConfig(t, validConfig)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Reconciler.MaxConcurrentReconciles != 0 {
		t.Fatalf("Reconciler.MaxConcurrentReconciles = %d, want 0 (absent key, caller applies the default)", cfg.Reconciler.MaxConcurrentReconciles)
	}
}

func TestLoadParsesReconcilerMaxConcurrentReconciles(t *testing.T) {
	path := writeConfig(t, validConfig+"\nreconciler:\n  max_concurrent_reconciles: 10\n")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Reconciler.MaxConcurrentReconciles != 10 {
		t.Fatalf("Reconciler.MaxConcurrentReconciles = %d, want 10", cfg.Reconciler.MaxConcurrentReconciles)
	}
}

func TestLoadRejectsNegativeMaxConcurrentReconciles(t *testing.T) {
	path := writeConfig(t, validConfig+"\nreconciler:\n  max_concurrent_reconciles: -1\n")

	if _, err := Load(path); err == nil {
		t.Fatalf("Load: want error for negative max_concurrent_reconciles")
	}
}

func TestLoadParsesReconcilerDefaultMode(t *testing.T) {
	path := writeConfig(t, validConfig+"\nreconciler:\n  default_mode: trigger\n")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Reconciler.DefaultMode != "trigger" {
		t.Fatalf("Reconciler.DefaultMode = %q, want %q", cfg.Reconciler.DefaultMode, "trigger")
	}
}

// TestLoadAcceptsAnyDefaultMode confirms default_mode is a free-form
// name, not a fixed enum: there is no whitelist of valid modes to
// enforce here — only ApiRegistration.Mode/DefaultMode both being empty is ever a
// problem, and that's a catalog.Reconciler.reconcile concern, not a
// load-time one.
func TestLoadAcceptsAnyDefaultMode(t *testing.T) {
	path := writeConfig(t, validConfig+"\nreconciler:\n  default_mode: anything-goes\n")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Reconciler.DefaultMode != "anything-goes" {
		t.Fatalf("Reconciler.DefaultMode = %q, want %q", cfg.Reconciler.DefaultMode, "anything-goes")
	}
}

const reconcilerModeConfig = `
reconciler:
  mode:
    api:
      - method: post
        endpoint: "https://{{ .Subscription.Api }}.local/sync"
        data:
          sync_id: "{{ .Subscription.ExpectedSyncID }}"
        headers:
          Content-Type: "application/json"
          Authorization:
            type: Bearer
            value: "tok"
        timeout: "3600s"
        async: true
        outputs:
          JobID: ".job_id"
      - method: get
        endpoint: "https://{{ .Subscription.Api }}.local/sync/{{ .Previous.Outputs.JobID }}"
        timeout: "3600s"
`

func TestLoadParsesStepWaitConditions(t *testing.T) {
	stepConfig := `
reconciler:
  mode:
    api:
      - method: get
        endpoint: "https://example.com/status"
        timeout: "3600s"
        wait:
          - key: .status
            successes: [done]
            failures: [skipped, canceled, failed]
`
	path := writeConfig(t, validConfig+stepConfig)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	steps := cfg.Reconciler.Mode["api"]
	if len(steps) != 1 || len(steps[0].Wait) != 1 {
		t.Fatalf("Reconciler.Mode[api] = %+v, want 1 step with 1 wait condition", steps)
	}
	cond := steps[0].Wait[0]
	if cond.Key != ".status" {
		t.Fatalf("wait[0].key = %q, want .status", cond.Key)
	}
	if len(cond.Successes) != 1 || cond.Successes[0] != "done" {
		t.Fatalf("wait[0].successes = %v, want [done]", cond.Successes)
	}
	if len(cond.Failures) != 3 {
		t.Fatalf("wait[0].failures = %v, want 3 entries", cond.Failures)
	}
}

func TestLoadRejectsStepWaitConditionMissingKey(t *testing.T) {
	stepConfig := `
reconciler:
  mode:
    api:
      - method: get
        endpoint: "https://example.com/status"
        timeout: "3600s"
        wait:
          - successes: [done]
`
	path := writeConfig(t, validConfig+stepConfig)

	if _, err := Load(path); err == nil {
		t.Fatalf("Load: want error for a wait condition with no key")
	}
}

func TestLoadParsesReconcilerModeSteps(t *testing.T) {
	path := writeConfig(t, validConfig+reconcilerModeConfig)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	steps, ok := cfg.Reconciler.Mode["api"]
	if !ok || len(steps) != 2 {
		t.Fatalf("Reconciler.Mode[api] = %+v, want 2 steps", steps)
	}

	first := steps[0]
	if first.Method != "post" || !first.Async {
		t.Fatalf("first step = %+v, want method=post async=true", first)
	}
	if first.Outputs["JobID"] != ".job_id" {
		t.Fatalf("first step outputs = %+v, want JobID=.job_id", first.Outputs)
	}
	ct := first.Headers["Content-Type"]
	if ct.Render() != "application/json" {
		t.Fatalf("Content-Type header renders to %q, want application/json", ct.Render())
	}
	auth := first.Headers["Authorization"]
	if auth.Render() != "Bearer tok" {
		t.Fatalf("Authorization header renders to %q, want %q", auth.Render(), "Bearer tok")
	}

	second := steps[1]
	if second.Method != "get" || second.Async {
		t.Fatalf("second step = %+v, want method=get async=false", second)
	}
}

// TestLoadParsesStepDataWithNestedVariablesList reproduces the shape
// that originally failed to parse: "data" is not always a flat string
// map — GitLab's pipeline-create API, for one, takes "variables" as a
// list of {key, value} objects.
func TestLoadParsesStepDataWithNestedVariablesList(t *testing.T) {
	stepConfig := `
reconciler:
  mode:
    trigger:
      - method: post
        endpoint: "https://gitlab.example.com/api/v4/projects/1/pipeline"
        data:
          ref: "{{ .Subscription.Platform }}"
          variables:
            - key: TG_KAYRA_TENANT_NAME
              value: "{{ .Subscription.Namespace }}"
            - key: PLUMBING_TERRAFORM_CHECK_MAX
              value: "50"
        timeout: "3600s"
`
	path := writeConfig(t, validConfig+stepConfig)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	steps := cfg.Reconciler.Mode["trigger"]
	if len(steps) != 1 {
		t.Fatalf("Reconciler.Mode[trigger] = %+v, want 1 step", steps)
	}

	variables, ok := steps[0].Data["variables"].([]any)
	if !ok || len(variables) != 2 {
		t.Fatalf("data.variables = %v, want 2 entries", steps[0].Data["variables"])
	}
	first, ok := variables[0].(map[string]any)
	if !ok || first["key"] != "TG_KAYRA_TENANT_NAME" {
		t.Fatalf("variables[0] = %v, want key=TG_KAYRA_TENANT_NAME", variables[0])
	}
}

func TestLoadRejectsStepMissingEndpoint(t *testing.T) {
	path := writeConfig(t, validConfig+"\nreconciler:\n  mode:\n    api:\n      - method: post\n        timeout: \"5s\"\n")

	if _, err := Load(path); err == nil {
		t.Fatalf("Load: want error for step with no endpoint")
	}
}

func TestLoadRejectsStepInvalidMethod(t *testing.T) {
	path := writeConfig(t, validConfig+"\nreconciler:\n  mode:\n    api:\n      - method: bogus\n        endpoint: \"https://example.com\"\n        timeout: \"5s\"\n")

	if _, err := Load(path); err == nil {
		t.Fatalf("Load: want error for step with invalid method")
	}
}

func TestLoadRejectsStepInvalidTimeout(t *testing.T) {
	path := writeConfig(t, validConfig+"\nreconciler:\n  mode:\n    api:\n      - method: get\n        endpoint: \"https://example.com\"\n        timeout: \"not-a-duration\"\n")

	if _, err := Load(path); err == nil {
		t.Fatalf("Load: want error for step with unparseable timeout")
	}
}

// claimsConfig is a minimal, standalone valid config whose sole
// authorizations entry is claims-backed — an Okta-style provider that
// resolves groups/attributes directly from its own userinfo response,
// with no ldap entry at all.
const claimsConfig = `
database:
  dev:
    local:
      path: /tmp/kayra-db
authentifications:
  okta:
    authorization: okta
    remote:
      enabled: true
      url: https://example.okta.com/.well-known/openid-configuration
      user_id:
        from: userinfo_endpoint
        field: sub
authorizations:
  okta:
    claims:
      from: userinfo_endpoint
      groups_field: MemberOf
      user_attributes:
        email: email
        employee_id: employeeNumber
`

func TestLoadAcceptsClaimsAuthorizationBackend(t *testing.T) {
	path := writeConfig(t, claimsConfig)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	claims := cfg.Authorizations["okta"].Claims
	if claims == nil {
		t.Fatalf("Authorizations[okta].Claims is nil")
	}
	if claims.From != "userinfo_endpoint" || claims.GroupsField != "MemberOf" {
		t.Fatalf("Claims = %+v, want From=userinfo_endpoint GroupsField=MemberOf", claims)
	}
	if claims.UserAttributes["email"] != "email" || claims.UserAttributes["employee_id"] != "employeeNumber" {
		t.Fatalf("Claims.UserAttributes = %v", claims.UserAttributes)
	}
}

func TestLoadRejectsClaimsWithoutGroupsField(t *testing.T) {
	bad := `
database:
  dev:
    local:
      path: /tmp/kayra-db
authentifications:
  okta:
    authorization: okta
    remote:
      enabled: true
      url: https://example.okta.com/.well-known/openid-configuration
      user_id:
        from: userinfo_endpoint
        field: sub
authorizations:
  okta:
    claims:
      from: userinfo_endpoint
`
	path := writeConfig(t, bad)
	if _, err := Load(path); err == nil {
		t.Fatalf("Load: want error for claims with no groups_field")
	}
}

func TestLoadRejectsClaimsInvalidFrom(t *testing.T) {
	bad := `
database:
  dev:
    local:
      path: /tmp/kayra-db
authentifications:
  okta:
    authorization: okta
    remote:
      enabled: true
      url: https://example.okta.com/.well-known/openid-configuration
      user_id:
        from: userinfo_endpoint
        field: sub
authorizations:
  okta:
    claims:
      from: something-else
      groups_field: MemberOf
`
	path := writeConfig(t, bad)
	if _, err := Load(path); err == nil {
		t.Fatalf("Load: want error for claims.from not one of token/userinfo_endpoint")
	}
}

func TestLoadRejectsClaimsInvalidGroupsFilter(t *testing.T) {
	bad := `
database:
  dev:
    local:
      path: /tmp/kayra-db
authentifications:
  okta:
    authorization: okta
    remote:
      enabled: true
      url: https://example.okta.com/.well-known/openid-configuration
      user_id:
        from: userinfo_endpoint
        field: sub
authorizations:
  okta:
    claims:
      from: userinfo_endpoint
      groups_field: MemberOf
      groups_filter: "(unclosed"
`
	path := writeConfig(t, bad)
	if _, err := Load(path); err == nil {
		t.Fatalf("Load: want error for an invalid groups_filter regex")
	}
}

func TestLoadRejectsLdapAndClaimsTogether(t *testing.T) {
	bad := `
database:
  dev:
    local:
      path: /tmp/kayra-db
authentifications:
  okta:
    authorization: okta
    remote:
      enabled: true
      url: https://example.okta.com/.well-known/openid-configuration
      user_id:
        from: userinfo_endpoint
        field: sub
authorizations:
  okta:
    claims:
      from: userinfo_endpoint
      groups_field: MemberOf
    ldap:
      enabled: true
      connection:
        host: ldap.example.com
      user:
        id: uid
        groups:
          member_attribute: memberof
          member_regex: '^cn=(sandbox-\w+-\w+),cn=groups,.*$'
`
	path := writeConfig(t, bad)
	if _, err := Load(path); err == nil {
		t.Fatalf("Load: want error for ldap and claims both set on the same authorizations entry")
	}
}

// TestLoadRejectsLocalProviderWithUserinfoClaims reproduces the runtime
// bug a self-signed token hit: authorizations.<name>.claims.from:
// userinfo_endpoint has no provider session to call back into when the
// referencing authentifications.<name> entry is local (self-signed) —
// provider.Remote is nil, so middleware would otherwise hand
// oidc.FetchDiscovery an empty URL. Load must now reject this
// combination outright instead of deferring to that confusing error.
func TestLoadRejectsLocalProviderWithUserinfoClaims(t *testing.T) {
	bad := `
database:
  dev:
    local:
      path: /tmp/kayra-db
authentifications:
  self:
    authorization: okta
    local:
      - kid: k1
        algorithm: RS256
        issuer: true
        secret: |
          dummy
authorizations:
  okta:
    claims:
      from: userinfo_endpoint
      groups_field: MemberOf
`
	path := writeConfig(t, bad)
	if _, err := Load(path); err == nil {
		t.Fatalf("Load: want error for a local provider pointed at a userinfo_endpoint claims backend")
	}
}

// TestLoadAcceptsLocalProviderWithTokenClaims confirms claims.from:
// token stays valid for a local provider — it reads the self-signed
// token's own embedded claims directly, with no remote call at all.
func TestLoadAcceptsLocalProviderWithTokenClaims(t *testing.T) {
	ok := `
database:
  dev:
    local:
      path: /tmp/kayra-db
authentifications:
  self:
    authorization: okta
    local:
      - kid: k1
        algorithm: RS256
        issuer: true
        secret: |
          dummy
authorizations:
  okta:
    claims:
      from: token
      groups_field: groups
`
	path := writeConfig(t, ok)
	if _, err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func TestLoadAcceptsRemoteProxyAndOAuth2(t *testing.T) {
	// claimsConfig already defines a valid okta/remote entry — extend it
	// in place rather than duplicating the whole fixture, by appending
	// proxy/oauth2 under the existing remote block.
	ok := strings.Replace(claimsConfig, "        field: sub\n", "        field: sub\n      proxy: http://proxy.corp.example:8080\n      oauth2:\n        client_id: cli-public-client\n        scopes: [openid, profile, email]\n", 1)

	path := writeConfig(t, ok)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	remote := cfg.Authentifications["okta"].Remote
	if remote.Proxy != "http://proxy.corp.example:8080" {
		t.Fatalf("Remote.Proxy = %q, want http://proxy.corp.example:8080", remote.Proxy)
	}
	if remote.OAuth2 == nil || remote.OAuth2.ClientID != "cli-public-client" {
		t.Fatalf("Remote.OAuth2 = %+v, want ClientID=cli-public-client", remote.OAuth2)
	}
	if len(remote.OAuth2.Scopes) != 3 || remote.OAuth2.Scopes[0] != "openid" {
		t.Fatalf("Remote.OAuth2.Scopes = %v", remote.OAuth2.Scopes)
	}
}

func TestLoadRejectsInvalidProxyURL(t *testing.T) {
	bad := strings.Replace(claimsConfig, "        field: sub\n", "        field: sub\n      proxy: \"http://[::1\"\n", 1)
	path := writeConfig(t, bad)
	if _, err := Load(path); err == nil {
		t.Fatalf("Load: want error for an unparseable remote.proxy")
	}
}

func TestLoadRejectsOAuth2WithoutClientID(t *testing.T) {
	bad := strings.Replace(claimsConfig, "        field: sub\n", "        field: sub\n      oauth2: {}\n", 1)
	path := writeConfig(t, bad)
	if _, err := Load(path); err == nil {
		t.Fatalf("Load: want error for oauth2 with no client_id")
	}
}
