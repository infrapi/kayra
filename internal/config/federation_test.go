package config

import (
	"strings"
	"testing"
)

func TestFederationValidate(t *testing.T) {
	ok := FederationConfig{Issuers: []FederationIssuer{
		{Issuer: "https://gitlab.example.com"},
		{Issuer: "https://token.actions.githubusercontent.com"},
		{Issuer: "http://127.0.0.1:8080", JWKSURL: "http://localhost:8080/keys"},
	}, Proxy: "http://proxy.example.com:3128"}
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	if i, found := ok.Issuer("https://gitlab.example.com"); !found || i.Issuer != "https://gitlab.example.com" {
		t.Fatal("Issuer")
	}
	if _, found := ok.Issuer("https://evil.example.com"); found {
		t.Fatal("an unlisted issuer found")
	}
	for c, want := range map[*FederationConfig]string{
		{Issuers: []FederationIssuer{{Issuer: "http://gitlab.example.com"}}}:                                  "https",
		{Issuers: []FederationIssuer{{Issuer: "gitlab.example.com"}}}:                                         "https",
		{Issuers: []FederationIssuer{{Issuer: "https://a.example.com"}, {Issuer: "https://a.example.com"}}}:   "twice",
		{Issuers: []FederationIssuer{{Issuer: "https://a.example.com", JWKSURL: "ftp://a.example.com/keys"}}}: "jwks_url",
		{Proxy: "::"}: "proxy",
	} {
		if err := c.validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", *c, err, want)
		}
	}
}
