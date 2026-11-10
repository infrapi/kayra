package catalog

import (
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"
	uuid "github.com/hashicorp/go-uuid"

	"github.com/infrapi/kayra/internal/httpapi"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// subscriptionSyncStatus is one active subscriber's sync state within
// apiRegistrationStatusResponse. Synced mirrors what a caller would
// otherwise have to compute themselves by comparing CurrentSyncID
// against the registration's own current SyncID (see
// subscriptionResponse in handlers_subscription.go, which does the
// same comparison for a single subscription).
type subscriptionSyncStatus struct {
	Namespace     string `json:"namespace"`
	State         string `json:"state"`
	CurrentSyncID string `json:"current_sync_id"`
	Synced        bool   `json:"synced"`
}

// apiRegistrationStatusResponse is the body of GET
// .../apiregistrations/:name/status: the registration's own current
// SyncID, plus every active subscription's own sync state against it.
// Inactive subscriptions (still pending the initial action — see
// Reconciler.handleNewSubscription) are omitted entirely: there is no
// sync state to report for one yet.
type apiRegistrationStatusResponse struct {
	Name          string                   `json:"name"`
	SyncID        string                   `json:"sync_id"`
	Subscriptions []subscriptionSyncStatus `json:"subscriptions"`
}

// validateApiRegistration checks that reg's name is a long api name
// (IsLongApiName), that its optional short_name is a single label not
// already used by another registration here, and that every
// entry in DependsOn resolves to an existing ApiRegistration — the
// legacy Postgres model enforced neither (no real FK, no app-level
// check either). Platform/Region need no check here:
// RegisterApiRegistrationRoutes always stamps them from this instance's
// own deployment config before validateApiRegistration ever sees reg,
// never from caller input.
func validateApiRegistration(repo *Repository, reg ApiRegistration) *liberrors.Error {
	if reg.Name == "" {
		return liberrors.New(http.StatusBadRequest, "catalog.ApiRegistration", "name is required")
	}
	if !IsLongApiName(reg.Name) {
		return liberrors.New(http.StatusBadRequest, "catalog.ApiRegistration", "name %q must be the api's long name, a lowercase DNS name such as \"compute.example.com\"", reg.Name)
	}
	if reg.ShortName != "" {
		if !IsShortApiName(reg.ShortName) {
			return liberrors.New(http.StatusBadRequest, "catalog.ApiRegistration", "short_name %q must be a single lowercase DNS label such as \"compute\"", reg.ShortName)
		}
		other, found, err := repo.findByShortName(reg.Platform, reg.Region, reg.ShortName)
		if err != nil {
			return liberrors.Wrap(err, http.StatusInternalServerError, "catalog.ApiRegistration", "")
		}
		if found && other.Name != reg.Name {
			return liberrors.New(http.StatusConflict, "catalog.ApiRegistration", "short_name %q is already used by api registration %q", reg.ShortName, other.Name)
		}
	}
	for _, dep := range reg.DependsOn {
		if dep.Platform == "" || dep.Region == "" || dep.Name == "" {
			return liberrors.New(http.StatusBadRequest, "catalog.ApiRegistration", "depends_on entries require platform, region and name")
		}
		if _, err := repo.GetClusterApiRegistration(dep.Platform, dep.Region, dep.Name); err != nil {
			return notFoundOrInternal(err, "catalog.ApiRegistration", "depends_on api registration %s/%s/%s not found", dep.Platform, dep.Region, dep.Name)
		}
	}
	return nil
}

// RegisterApiRegistrationRoutes mounts cluster-wide ApiRegistration CRUD
// at /apis/catalog.example.com/v1/apiregistrations (its own API group —
// an ApiRegistration isn't one of internal/rbac's cluster RBAC objects,
// it just happens to share the same trust tier) behind gate (normally
// middleware.SysadminGate). Ported from the legacy Postgres "stacks"
// table; DependsOn replaces that model's separate "dependencies" table
// (see types.go). deploymentPlatform/deploymentRegion are this
// instance's own INFRAPI_APP_PLATFORM/_REGION: every route here
// addresses a registration within that scope alone — there is no
// platform/region path segment or request field, since this instance
// already knows its own and a caller repeating it on every request
// would only ever be able to say the one value that's already true. A
// DependsOn entry is the one place platform/region still appears
// explicitly: the legacy model let a dependency cross platform/region,
// and that's unchanged.
func RegisterApiRegistrationRoutes(r gin.IRouter, repo *Repository, gate gin.HandlerFunc, deploymentPlatform, deploymentRegion string) {
	group := r.Group("/apis/"+CatalogAPI+"/v1", gate)

	group.POST("/apiregistrations", func(c *gin.Context) {
		var reg ApiRegistration
		if err := c.ShouldBindJSON(&reg); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "catalog.CreateApiRegistration", ""))
			return
		}
		reg.Platform, reg.Region = deploymentPlatform, deploymentRegion
		// A registration created with no explicit sync_id gets one
		// minted here rather than kept empty: Reconciler never
		// reconciles a registration whose SyncID is empty (see
		// ensureReconciled), so a kickstarted registration with nothing
		// to reconcile to would otherwise leave every subscriber it
		// ever gains stuck pending until someone remembers to PUT
		// .../sync by hand. A caller that already named an explicit
		// sync_id keeps it.
		if reg.SyncID == "" {
			syncID, err := uuid.GenerateUUID()
			if err != nil {
				httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.CreateApiRegistration", ""))
				return
			}
			reg.SyncID = syncID
		}
		if err := validateApiRegistration(repo, reg); err != nil {
			httpapi.Fail(c, err)
			return
		}
		if err := repo.PutClusterApiRegistration(&reg); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.CreateApiRegistration", ""))
			return
		}
		c.JSON(http.StatusCreated, reg)
	})

	// GET /apiregistrations only ever lists this instance's own
	// platform/region: every other route here can only address a
	// registration in that same scope, so listing anything wider would
	// list registrations the rest of this API couldn't individually
	// reach by name anyway.
	group.GET("/apiregistrations", func(c *gin.Context) {
		all, err := repo.ListClusterApiRegistrations()
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.ListApiRegistrations", ""))
			return
		}
		regs := make([]ApiRegistration, 0, len(all))
		for _, reg := range all {
			if reg.Platform == deploymentPlatform && reg.Region == deploymentRegion {
				regs = append(regs, reg)
			}
		}
		c.JSON(http.StatusOK, regs)
	})

	group.GET("/apiregistrations/:name", func(c *gin.Context) {
		reg, err := repo.GetClusterApiRegistration(deploymentPlatform, deploymentRegion, c.Param("name"))
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "catalog.GetApiRegistration", "api registration %q not found", c.Param("name")))
			return
		}
		c.JSON(http.StatusOK, reg)
	})

	// GET .../status reports every active subscription's sync state
	// against this registration's current SyncID in one call, rather
	// than making a caller list subscriptions per-namespace and compare
	// each one's expected_sync_id by hand.
	group.GET("/apiregistrations/:name/status", func(c *gin.Context) {
		name := c.Param("name")
		reg, err := repo.GetClusterApiRegistration(deploymentPlatform, deploymentRegion, name)
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "catalog.ApiRegistrationStatus", "api registration %q not found", name))
			return
		}

		subs, err := repo.ListSubscriptionsToApi(name)
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.ApiRegistrationStatus", ""))
			return
		}

		resp := apiRegistrationStatusResponse{Name: reg.Name, SyncID: reg.SyncID, Subscriptions: []subscriptionSyncStatus{}}
		for namespace, sub := range subs {
			if !sub.Active {
				continue
			}
			resp.Subscriptions = append(resp.Subscriptions, subscriptionSyncStatus{
				Namespace:     namespace,
				State:         sub.State,
				CurrentSyncID: sub.CurrentSyncID,
				Synced:        sub.CurrentSyncID == reg.SyncID,
			})
		}
		// ListSubscriptionsToApi returns a map, so iteration order is
		// otherwise random — sort by namespace for a stable response.
		sort.Slice(resp.Subscriptions, func(i, j int) bool {
			return resp.Subscriptions[i].Namespace < resp.Subscriptions[j].Namespace
		})
		c.JSON(http.StatusOK, resp)
	})

	group.PUT("/apiregistrations/:name", func(c *gin.Context) {
		name := c.Param("name")
		existing, err := repo.GetClusterApiRegistration(deploymentPlatform, deploymentRegion, name)
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "catalog.UpdateApiRegistration", "api registration %q not found", name))
			return
		}

		var reg ApiRegistration
		if err := c.ShouldBindJSON(&reg); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "catalog.UpdateApiRegistration", ""))
			return
		}
		reg.Platform, reg.Region, reg.Name = deploymentPlatform, deploymentRegion, name
		// CanaryNamespaces is pipeline state for an in-progress canary
		// rollout (see ApiRegistration), not something this
		// general-purpose update ever touches — only PUT .../sync
		// manages it.
		reg.CanaryNamespaces = existing.CanaryNamespaces
		if err := validateApiRegistration(repo, reg); err != nil {
			httpapi.Fail(c, err)
			return
		}

		if err := repo.PutClusterApiRegistration(&reg); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.UpdateApiRegistration", ""))
			return
		}
		c.JSON(http.StatusOK, reg)
	})

	// PUT .../sync is the shorthand reconcile trigger. Its optional body
	// names canary_namespaces to start (or replace) a canary rollout —
	// see ApiRegistration.CanaryNamespaces — rather than the ordinary
	// full fan-out; an empty/absent body falls back to that ordinary
	// behavior, unless a canary rollout is already pending, in which
	// case it's a release (see the switch below).
	group.PUT("/apiregistrations/:name/sync", func(c *gin.Context) {
		name := c.Param("name")
		reg, err := repo.GetClusterApiRegistration(deploymentPlatform, deploymentRegion, name)
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "catalog.SyncApiRegistration", "api registration %q not found", name))
			return
		}

		var req struct {
			CanaryNamespaces []string `json:"canary_namespaces"`
		}
		if c.Request.ContentLength > 0 {
			if err := c.ShouldBindJSON(&req); err != nil {
				httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "catalog.SyncApiRegistration", ""))
				return
			}
		}

		switch {
		case len(req.CanaryNamespaces) > 0:
			// Start (or replace) a canary rollout: a fresh target
			// SyncID, but Reconciler only reconciles these namespaces
			// for now — see ApiRegistration.CanaryNamespaces and
			// handleApiRegistrationPut.
			for _, ns := range req.CanaryNamespaces {
				if _, err := repo.GetNamespaceSubscription(ns, name); err != nil {
					httpapi.Fail(c, notFoundOrInternal(err, "catalog.SyncApiRegistration", "namespace %q is not subscribed to %q", ns, name))
					return
				}
			}
			syncID, err := uuid.GenerateUUID()
			if err != nil {
				httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.SyncApiRegistration", ""))
				return
			}
			reg.SyncID = syncID
			reg.CanaryNamespaces = req.CanaryNamespaces

		case len(reg.CanaryNamespaces) > 0:
			// Release: no canary_namespaces named, and a canary rollout
			// is already pending — fan the SAME SyncID the canary
			// already validated out to everyone else, rather than
			// minting a new one they'd all have to adopt separately.
			reg.CanaryNamespaces = nil

		default:
			// Ordinary case, no canary involved at all: a fresh target
			// SyncID for every active subscriber at once, same as
			// always.
			syncID, err := uuid.GenerateUUID()
			if err != nil {
				httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.SyncApiRegistration", ""))
				return
			}
			reg.SyncID = syncID
		}

		if err := repo.PutClusterApiRegistration(&reg); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.SyncApiRegistration", ""))
			return
		}
		c.JSON(http.StatusOK, reg)
	})

	group.DELETE("/apiregistrations/:name", func(c *gin.Context) {
		name := c.Param("name")
		if _, err := repo.GetClusterApiRegistration(deploymentPlatform, deploymentRegion, name); err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "catalog.DeleteApiRegistration", "api registration %q not found", name))
			return
		}

		referenced, err := repo.apiRegistrationIsReferenced(deploymentPlatform, deploymentRegion, name, deploymentPlatform, deploymentRegion)
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.DeleteApiRegistration", ""))
			return
		}
		if referenced {
			httpapi.Fail(c, liberrors.New(http.StatusConflict, "catalog.DeleteApiRegistration",
				"api registration %q is still referenced by another registration's depends_on or by a subscription", name))
			return
		}

		if err := repo.DeleteClusterApiRegistration(deploymentPlatform, deploymentRegion, name); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.DeleteApiRegistration", ""))
			return
		}
		c.Status(http.StatusNoContent)
	})
}
