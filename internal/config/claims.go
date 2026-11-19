package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// ClaimValues are the values a claim may take: written as one value, or
// a list.
type ClaimValues []string

// UnmarshalYAML reads a value alone, or a list of them.
func (v *ClaimValues) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		*v = ClaimValues{n.Value}
		return nil
	case yaml.SequenceNode:
		var list []string
		if err := n.Decode(&list); err != nil {
			return err
		}
		*v = list
		return nil
	}
	return fmt.Errorf("line %d: a claim's values are a value or a list of them", n.Line)
}

// RenderClaims renders $region and $platform, this instance's, in every
// remote provider's claims values and every local key's audiences: what a
// token is checked, and signed, against.
func (c *Config) RenderClaims(region, platform string) {
	r := strings.NewReplacer("$region", region, "$platform", platform)
	for name, p := range c.Authentifications {
		if p.Remote != nil {
			for k, values := range p.Remote.Claims {
				for i, v := range values {
					values[i] = r.Replace(v)
				}
				p.Remote.Claims[k] = values
			}
		}
		for i := range p.Local {
			for j, a := range p.Local[i].Audiences {
				p.Local[i].Audiences[j] = r.Replace(a)
			}
		}
		c.Authentifications[name] = p
	}
}
