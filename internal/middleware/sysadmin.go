package middleware

// SysadminGroupFor renders the spec's "$platform-core-sysadmin" template:
// $platform is a variable substituted with this instance's own configured
// platform (INFRAPI_APP_PLATFORM, e.g. "sandbox"), so the real group name
// required is e.g. "sandbox-core-sysadmin" — an actual LDAP/IdP group, not
// a literal string to match verbatim. This is only ever the *default*
// group of the built-in sysadmin binding (rbac.Repository.SetSysadmin)
// when config.SysadminConfig.Groups is left empty — a deployment that
// names its own groups there never sees this template at all.
func SysadminGroupFor(platform string) string {
	return platform + "-core-sysadmin"
}
