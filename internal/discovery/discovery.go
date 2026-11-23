// Package discovery serves Kayra's own discovery document,
// /.well-known/kayra.json: its API domain (app.api_domain), the paths of
// its built-in API groups and the endpoints clients call, so neither apps
// built on infrapi/lib nor infrapi-cli configure any of them. It describes
// Kayra itself, not the catalog: every API group, whatever its domain, is
// listed by GET /apis.
package discovery

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Path is where the document is served, without authentication.
const Path = "/.well-known/kayra.json"

// Document is the content of Path. Paths are relative to Kayra's URL, so
// they hold behind a gateway that serves Kayra on its own host.
type Document struct {
	// Issuer is Kayra's public URL, app.url: its authorization server's
	// issuer, what an app's protected resource metadata names (RFC 9728),
	// for an OAuth client to fetch its metadata from.
	Issuer string `json:"issuer"`
	// Domain is app.api_domain: Kayra's built-in groups are
	// <name>.<Domain>. Other APIs' groups are their own full names.
	Domain string `json:"domain"`
	// APIs maps each built-in group's name (system, catalog,
	// authorization, events) to its path, /apis/<name>.<Domain>/v1.
	APIs map[string]string `json:"apis"`
	// Endpoints are the paths clients call.
	Endpoints Endpoints `json:"endpoints"`
}

// Endpoints are the paths of Kayra's endpoints a client calls.
type Endpoints struct {
	// Userinfo resolves a bearer token to its identity (GET or POST).
	Userinfo string `json:"userinfo"`
	// Check decides whether a caller may act (POST): RBAC's authorize.
	Check string `json:"check"`
	// JWKS is the public keys of Kayra's self-signed tokens.
	JWKS string `json:"jwks"`
	// APIs is the discovery of every API group, Kayra's and the
	// registered ones, with their resources and short names.
	APIs string `json:"apis"`
}

// Groups are the names and full names of Kayra's built-in API groups, as
// rbac and catalog define them once the domain is set.
type Groups struct {
	System, Catalog, Authorization, Events string
}

// New builds the document of a Kayra on domain, its built-in groups named
// by groups.
func New(issuer, domain string, groups Groups, userinfo, jwks, apis string) Document {
	root := func(group string) string { return "/apis/" + group + "/v1" }
	return Document{
		Issuer: strings.TrimRight(issuer, "/"),
		Domain: domain,
		APIs: map[string]string{
			"system":        root(groups.System),
			"catalog":       root(groups.Catalog),
			"authorization": root(groups.Authorization),
			"events":        root(groups.Events),
		},
		Endpoints: Endpoints{
			Userinfo: userinfo,
			Check:    root(groups.Authorization) + "/check",
			JWKS:     jwks,
			APIs:     apis,
		},
	}
}

// Register serves doc at Path. It changes only with Kayra's configuration:
// clients may cache it.
func Register(r gin.IRouter, doc Document) {
	r.GET(Path, func(c *gin.Context) {
		c.Header("Cache-Control", "public, max-age=300")
		c.JSON(http.StatusOK, doc)
	})
}
