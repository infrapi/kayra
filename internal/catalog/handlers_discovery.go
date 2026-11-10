package catalog

import (
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// DiscoveryGroup is one api group GET /apis lists: one of Kayra's own
// (Builtin, resources derived from its live route table) or a
// registered app (resources derived from the OpenAPI spec the
// Reconciler last fetched for it — see ApiSpec).
type DiscoveryGroup struct {
	Api       string `json:"api"`
	ShortName string `json:"short_name"`
	Owner     string `json:"owner"`
	Builtin   bool   `json:"builtin"`
	// SyncID is the registration's current sync_id; SpecSyncID the one
	// its stored spec was fetched for. They differ while a sync is
	// pending, and SpecSyncID is "" (no resources) until the first one.
	SyncID     string        `json:"sync_id"`
	SpecSyncID string        `json:"spec_sync_id"`
	Resources  []ApiResource `json:"resources"`
}

// builtinOwner is what Kayra's own groups list as their owner.
const builtinOwner = "kayra"

// RegisterDiscoveryRoutes mounts, behind gate (normally
// middleware.Authenticator: any authenticated caller — tenants need it
// to see what they can subscribe to; the resources themselves stay
// gated as they are):
//
//   - GET /apis: every api group and its resources (DiscoveryGroup),
//     Kayra's own first;
//   - GET /apis/catalog.<domain>/v1/apiregistrations/{name}/openapi.json:
//     a registration's stored spec, exactly as the app served it.
//
// routes returns Kayra's own route table (engine.Routes()), read per
// request so it always matches what this server actually serves.
func RegisterDiscoveryRoutes(r gin.IRouter, repo *Repository, gate gin.HandlerFunc, routes func() []Route, deploymentPlatform, deploymentRegion string) {
	r.GET("/apis", gate, func(c *gin.Context) {
		const origin = "catalog.Discovery"
		groups := builtinGroups(routes())

		regs, err := repo.ListClusterApiRegistrations()
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin+".ListClusterApiRegistrations", ""))
			return
		}
		var registered []DiscoveryGroup
		for _, reg := range regs {
			if reg.Platform != deploymentPlatform || reg.Region != deploymentRegion {
				continue
			}
			g := DiscoveryGroup{Api: reg.Name, ShortName: reg.ShortName, Owner: reg.Owner, SyncID: reg.SyncID, Resources: []ApiResource{}}
			spec, err := repo.GetApiSpec(reg.Platform, reg.Region, reg.Name)
			switch {
			case err == nil:
				g.SpecSyncID = spec.SyncID
				if spec.Resources != nil {
					g.Resources = spec.Resources
				}
			case err != store.ErrNotFound:
				httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin+".GetApiSpec", ""))
				return
			}
			registered = append(registered, g)
		}
		sort.Slice(registered, func(i, j int) bool { return registered[i].Api < registered[j].Api })

		c.JSON(http.StatusOK, append(groups, registered...))
	})

	r.GET("/apis/"+CatalogAPI+"/v1/apiregistrations/:name/openapi.json", gate, func(c *gin.Context) {
		const origin = "catalog.GetApiSpec"
		name := c.Param("name")
		if _, err := repo.GetClusterApiRegistration(deploymentPlatform, deploymentRegion, name); err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, origin, "api registration %q not found", name))
			return
		}
		spec, err := repo.GetApiSpec(deploymentPlatform, deploymentRegion, name)
		if err != nil {
			lerr := notFoundOrInternal(err, origin, "no openapi spec stored for api %q yet", name)
			if lerr.Code == http.StatusNotFound {
				lerr = lerr.WithSolution("the spec is fetched from the app at its next sync: bump the registration's sync_id, and check the reconciler's logs if it still doesn't appear")
			}
			httpapi.Fail(c, lerr)
			return
		}
		c.Data(http.StatusOK, "application/json", spec.Spec)
	})
}

// builtinGroups derives Kayra's own api groups from its route table:
// every /apis/<group>/v1/... route, grouped by <group>.
func builtinGroups(routes []Route) []DiscoveryGroup {
	byApi := map[string][]Route{}
	for _, rt := range routes {
		rest, ok := strings.CutPrefix(rt.Path, "/apis/")
		if !ok {
			continue
		}
		api, _, _ := strings.Cut(rest, "/")
		if api == "" || isPathParam(api) {
			continue
		}
		byApi[api] = append(byApi[api], rt)
	}
	groups := make([]DiscoveryGroup, 0, len(byApi))
	for api, rts := range byApi {
		resources := DeriveResources(api, rts)
		if len(resources) == 0 {
			continue
		}
		groups = append(groups, DiscoveryGroup{Api: api, Owner: builtinOwner, Builtin: true, Resources: resources})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Api < groups[j].Api })
	return groups
}
