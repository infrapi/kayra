package config

import (
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

// A claim's values: one, or a list; $region and $platform rendered, the
// local keys' audiences' too.
func TestClaims(t *testing.T) {
	var r RemoteAuthConfig
	if err := yaml.Unmarshal([]byte("claims:\n  cid: 0oa1\n  aud: [api://infrapi-$region-$platform, kayra]\n"), &r); err != nil {
		t.Fatal(err)
	}
	c := &Config{Authentifications: map[string]AuthProvider{
		"okta": {Remote: &r},
		"self": {Local: []LocalSigningKey{{Kid: "k1", Audiences: []string{"infrapi-$region"}}}},
	}}
	c.RenderClaims("eu-west-1", "sandbox")
	claims := c.Authentifications["okta"].Remote.Claims
	if !slices.Equal(claims["cid"], ClaimValues{"0oa1"}) || !slices.Equal(claims["aud"], ClaimValues{"api://infrapi-eu-west-1-sandbox", "kayra"}) {
		t.Errorf("claims: %v", claims)
	}
	if got := c.Authentifications["self"].Local[0].Audiences; !slices.Equal(got, []string{"infrapi-eu-west-1"}) {
		t.Errorf("self: %v", got)
	}
	if err := yaml.Unmarshal([]byte("claims:\n  cid: {a: b}\n"), &r); err == nil {
		t.Error("a map as values: accepted")
	}
}
