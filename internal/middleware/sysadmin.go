package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	gcrypto "github.com/infrapi/kayra/internal/crypto"
	"github.com/infrapi/kayra/internal/httpapi"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// SysadminGroupFor renders the spec's "$platform-core-sysadmin" template:
// $platform is a variable substituted with this instance's own configured
// platform (INFRAPI_APP_PLATFORM, e.g. "sandbox"), so the real group name
// required is e.g. "sandbox-core-sysadmin" — an actual LDAP/IdP group, not
// a literal string to match verbatim. This is only ever the *default*
// requiredGroups SysadminGate falls back to when config.SysadminConfig.Groups
// is left empty — a deployment that names its own groups there never sees
// this template at all.
func SysadminGroupFor(platform string) string {
	return platform + "-core-sysadmin"
}

// SysadminGate authenticates a request exactly the way Authenticator's own
// general-purpose Middleware does — any configured authentifications.<name>
// (a self-signed local JWT, a remote OIDC/OAuth2 provider's token, or a
// PAT), through the identical resolveJWT/resolvePAT resolution — and
// additionally requires the resolved identity's Groups to intersect
// requiredGroups. There is deliberately no separate trust path for
// "sysadmin" tokens: the privilege is just a caller whose directory/claims
// group membership happens to match one of requiredGroups, resolved the
// same live way (or, for a claims-backed authorizations.<name>, from the
// same already-verified token) any other endpoint would. requiredGroups
// itself always comes from config.SysadminConfig.Groups — see
// SysadminGroupFor for the one-group default a deployment falls back to
// when it configures none.
func SysadminGate(a *Authenticator, requiredGroups []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := extractBearer(c.GetHeader("Authorization"))
		if err != nil {
			httpapi.Fail(c, liberrors.New(http.StatusUnauthorized, "middleware.SysadminGate", "%s", err))
			return
		}

		var ac *AuthContext
		if gcrypto.IsToken(token) {
			ac, err = a.resolvePAT(token)
		} else {
			ac, err = a.resolveJWT(token)
		}
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusUnauthorized, "middleware.SysadminGate", ""))
			return
		}

		if !hasAnyGroup(ac.Groups, requiredGroups) {
			httpapi.Fail(c, liberrors.New(http.StatusForbidden, "middleware.SysadminGate", "none of the caller's groups match a configured sysadmin group"))
			return
		}

		SetAuth(c, ac)
		c.Next()
	}
}

// hasAnyGroup reports whether groups and required share at least one
// entry.
func hasAnyGroup(groups, required []string) bool {
	set := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		set[g] = struct{}{}
	}
	for _, r := range required {
		if _, ok := set[r]; ok {
			return true
		}
	}
	return false
}
