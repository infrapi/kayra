package config

import (
	"fmt"
	"time"
)

// MaxServiceAccountTokenTTL caps serviceaccounts.max_token_ttl: a service
// account's token is short-lived, a CI gets a new one from its platform's
// identity (federation) rather than keeping a long one.
const MaxServiceAccountTokenTTL = 24 * time.Hour

// ServiceAccountsConfig is the serviceaccounts: block: the lifetimes of the
// tokens a namespace's service accounts are issued
// (POST .../serviceaccounts/<name>/token). Issuing them needs the
// authorization server (oauth2.enabled), whose signer signs them.
type ServiceAccountsConfig struct {
	// TokenTTL is a token's lifetime when the request names none: 1h.
	TokenTTL string `yaml:"token_ttl"`
	// MaxTokenTTL is the longest a request may ask for: 24h, at most
	// MaxServiceAccountTokenTTL.
	MaxTokenTTL string `yaml:"max_token_ttl"`
}

// ServiceAccountDurations are the parsed lifetimes.
type ServiceAccountDurations struct{ Default, Max time.Duration }

// Durations parses the lifetimes, their defaults when unset, and checks
// the default is within the maximum, and the maximum within
// MaxServiceAccountTokenTTL.
func (s ServiceAccountsConfig) Durations() (ServiceAccountDurations, error) {
	var d ServiceAccountDurations
	for _, f := range []struct {
		name, raw, def string
		into           *time.Duration
	}{
		{"token_ttl", s.TokenTTL, "1h", &d.Default},
		{"max_token_ttl", s.MaxTokenTTL, "24h", &d.Max},
	} {
		raw := f.raw
		if raw == "" {
			raw = f.def
		}
		v, err := time.ParseDuration(raw)
		if err != nil || v <= 0 {
			return d, fmt.Errorf("serviceaccounts.%s %q: a duration", f.name, f.raw)
		}
		*f.into = v
	}
	if d.Max > MaxServiceAccountTokenTTL {
		return d, fmt.Errorf("serviceaccounts.max_token_ttl %s: at most %s, a CI uses federation for longer", d.Max, MaxServiceAccountTokenTTL)
	}
	if d.Default > d.Max {
		return d, fmt.Errorf("serviceaccounts.token_ttl %s: more than max_token_ttl %s", d.Default, d.Max)
	}
	return d, nil
}
