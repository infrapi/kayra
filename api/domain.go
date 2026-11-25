package api

import (
	"bytes"
	"strings"

	"github.com/infrapi/lib/pkg/server"
)

// contractDomain is the domain the contracts are written for.
const contractDomain = "infrapi.io"

// domain is the one they are served under: SetDomain's.
var domain = contractDomain

// SetDomain serves Kayra's APIs under domain, app.api_domain: each group
// <name>.infrapi.io becomes <name>.<domain>, with its roots, so the routes
// Register mounts and the contracts Served follow. Call it once, before
// either.
func SetDomain(d string) {
	if d == "" {
		d = contractDomain
	}
	domain = d
	for _, g := range []struct {
		group *string
		roots []string
	}{{&SystemGroup, SystemRoots}, {&CatalogGroup, CatalogRoots}, {&RbacGroup, RbacRoots}, {&EventsGroup, EventsRoots}} {
		old := *g.group
		*g.group = rebase(old)
		for i, r := range g.roots {
			g.roots[i] = strings.Replace(r, "/apis/"+old+"/", "/apis/"+*g.group+"/", 1)
		}
	}
}

// rebase is group, <name>.infrapi.io, under the domain.
func rebase(group string) string {
	name, _, _ := strings.Cut(group, ".")
	return name + "." + domain
}

// Served are the contracts as Kayra serves them, server.WithOpenAPI's:
// their groups, in their paths and info.x-infrapi-group, under the
// domain. An example's group, compute.infrapi.io, stays.
func Served() []server.OpenAPISpec {
	specs := Contracts()
	for i, s := range specs {
		content := s.Content
		for _, name := range []string{"system", "catalog", "authorization", "events"} {
			from := name + "." + contractDomain
			to := name + "." + domain
			content = bytes.ReplaceAll(content, []byte("/apis/"+from+"/"), []byte("/apis/"+to+"/"))
			content = bytes.ReplaceAll(content, []byte("x-infrapi-group: "+from+"\n"), []byte("x-infrapi-group: "+to+"\n"))
		}
		specs[i].Content = content
	}
	return specs
}
