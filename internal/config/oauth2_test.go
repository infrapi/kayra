package config

import (
	"strings"
	"testing"
)

func TestOAuth2ServerValidate(t *testing.T) {
	base := func() *Config {
		return &Config{Authentifications: map[string]AuthProvider{
			"okta": {Remote: &RemoteAuthConfig{Enabled: true, URL: "https://okta.example.com", OAuth2: &OAuth2LoginConfig{ClientID: "0oa1"}}},
			"ci":   {Remote: &RemoteAuthConfig{Enabled: true, URL: "https://gitlab.example.com"}},
			"self": {Local: []LocalSigningKey{{Enabled: true, Issuer: true, Kid: "k1"}}},
		}}
	}
	good := OAuth2ServerConfig{Enabled: true, Clients: []OAuth2Client{{ID: "infrapi-cli", RedirectURIs: []string{"http://127.0.0.1/callback"}}}}
	c := base()
	if err := good.validate(c); err != nil {
		t.Fatalf("good: %v", err)
	}
	if d, _ := good.Durations(); d.Access.Minutes() != 15 || d.Refresh.Hours() != 720 || d.Idle.Hours() != 168 {
		t.Errorf("defaults: %+v", d)
	}
	for name, c2 := range map[string]struct {
		edit func(*OAuth2ServerConfig)
		want string
	}{
		"no signer":        {func(o *OAuth2ServerConfig) { o.Signer = "okta" }, "oauth2.signer"},
		"a bad duration":   {func(o *OAuth2ServerConfig) { o.AccessTokenTTL = "soon" }, "access_token_ttl"},
		"a bad resource":   {func(o *OAuth2ServerConfig) { o.Resources = []string{"kayra.example.com"} }, "oauth2.resources"},
		"an http redirect": {func(o *OAuth2ServerConfig) { o.Clients[0].RedirectURIs = []string{"http://app.example.com/cb"} }, "loopback"},
		"a URL client id":  {func(o *OAuth2ServerConfig) { o.Clients[0].ID = "https://x.example.com/c.json" }, "not a URL"},
		"no redirect":      {func(o *OAuth2ServerConfig) { o.Clients[0].RedirectURIs = nil }, "redirect_uris is required"},
	} {
		o := good
		o.Clients = append([]OAuth2Client(nil), good.Clients...)
		c2.edit(&o)
		if err := o.validate(base()); err == nil || !strings.Contains(err.Error(), c2.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got := c.LoginProviders(); len(got) != 1 || got[0] != "okta" {
		t.Errorf("login providers: %v, the ci one has no oauth2", got)
	}
	none := base()
	none.Authentifications["okta"].Remote.OAuth2 = nil
	if err := good.validate(none); err == nil || !strings.Contains(err.Error(), "nowhere to log in") {
		t.Errorf("no provider with oauth2: %v", err)
	}
	off := OAuth2ServerConfig{}
	if err := off.validate(none); err != nil {
		t.Errorf("disabled: %v", err)
	}
}
