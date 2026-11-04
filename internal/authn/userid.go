package authn

import (
	"fmt"
	"regexp"

	"github.com/infrapi/kayra/internal/config"
)

// ResolveUserID extracts the user id out of v per cfg: either a claim
// (optionally narrowed by a regexp's first capture group), or a field in
// the provider's real userinfo_endpoint response.
func ResolveUserID(v *Verified, cfg config.UserIDConfig, remoteURL, proxy string) (string, error) {
	source, err := claimsSource(v, cfg.From, remoteURL, proxy)
	if err != nil {
		return "", err
	}

	raw, ok := source[cfg.Field]
	if !ok {
		return "", fmt.Errorf("authn: claims source has no field %q", cfg.Field)
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("authn: claims field %q is not a string", cfg.Field)
	}
	return applyFilter(value, cfg.Filter)
}

// applyFilter narrows value to filter's first capture group, when filter is
// set — e.g. '^([^@]+)@' to take "jdoe" out of "jdoe@company.com".
func applyFilter(value, filter string) (string, error) {
	if filter == "" {
		return value, nil
	}
	re, err := regexp.Compile(filter)
	if err != nil {
		return "", fmt.Errorf("authn: compile filter %q: %w", filter, err)
	}
	match := re.FindStringSubmatch(value)
	if len(match) < 2 {
		return "", fmt.Errorf("authn: filter %q did not match %q", filter, value)
	}
	return match[1], nil
}

// claimsSource returns the raw claim/field map ResolveUserID,
// ResolveGroups and ResolveAttributes all read from: v's own
// already-verified token claims (jwt.MapClaims is itself a
// map[string]any, so this is free), or the provider's userinfo_endpoint
// response — fetched once per token and cached on v itself (see
// Verified.fetchUserinfo), since all three may need it for the very
// same request (a claims-backed authorizations.<name> entry resolves
// both Groups and Attributes from it, on top of ResolveUserID's own
// use) and there is no reason to hit the provider's userinfo endpoint
// more than once for that.
func claimsSource(v *Verified, from, remoteURL, proxy string) (map[string]any, error) {
	switch from {
	case "token":
		return v.Claims, nil

	case "userinfo_endpoint":
		return v.fetchUserinfo(remoteURL, proxy)

	default:
		return nil, fmt.Errorf("authn: unsupported claims.from %q", from)
	}
}

// ResolveGroups extracts a caller's group membership directly out of
// v's own already-verified token claims or userinfo response, per cfg
// — the claims-backed twin of authz.Authorizer.ResolveUser's Groups,
// for a provider (Okta, say) whose token/userinfo already carries real
// group membership, with no directory to look it up in separately.
// field must hold a JSON array of strings (e.g. Okta's own "MemberOf");
// filter, when set, is applied independently to each element exactly
// like authorizations.<name>.ldap.user.groups.member_regex does to a
// real memberOf value — an element that doesn't match is dropped, one
// that does contributes its first capture group (or the whole match,
// when filter has no capture group) to the result.
func ResolveGroups(v *Verified, from, field, filter, remoteURL, proxy string) ([]string, error) {
	source, err := claimsSource(v, from, remoteURL, proxy)
	if err != nil {
		return nil, err
	}

	raw, ok := source[field]
	if !ok {
		return nil, fmt.Errorf("authn: claims source has no field %q", field)
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("authn: claims field %q is not a list", field)
	}

	var re *regexp.Regexp
	if filter != "" {
		re, err = regexp.Compile(filter)
		if err != nil {
			return nil, fmt.Errorf("authn: compile groups_filter %q: %w", filter, err)
		}
	}

	groups := make([]string, 0, len(list))
	for _, item := range list {
		value, ok := item.(string)
		if !ok {
			continue
		}
		if re == nil {
			groups = append(groups, value)
			continue
		}
		match := re.FindStringSubmatch(value)
		if match == nil {
			continue
		}
		if len(match) > 1 {
			groups = append(groups, match[1])
		} else {
			groups = append(groups, match[0])
		}
	}
	return groups, nil
}

// ResolveAttributes extracts userAttributes (local name -> claims/
// userinfo field, the same shape authorizations.<name>.ldap.user.
// user_attributes uses) out of v's own token claims or userinfo
// response, per from/remoteURL — ResolveGroups' sibling for the
// attributes half of a claims-backed authorizations.<name> entry. A
// named field absent from the source, or not a string, resolves to ""
// rather than failing the whole resolution or omitting the key —
// exactly how a missing LDAP attribute already behaves
// (ldap.Entry.GetAttributeValue's own zero value), so a caller never
// has to treat the two backends differently.
func ResolveAttributes(v *Verified, from string, userAttributes map[string]string, remoteURL, proxy string) (map[string]string, error) {
	source, err := claimsSource(v, from, remoteURL, proxy)
	if err != nil {
		return nil, err
	}

	attrs := make(map[string]string, len(userAttributes))
	for localName, field := range userAttributes {
		value, _ := source[field].(string)
		attrs[localName] = value
	}
	return attrs, nil
}
