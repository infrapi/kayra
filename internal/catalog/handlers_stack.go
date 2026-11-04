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
// stackStatusResponse. Synced mirrors what a caller would otherwise have
// to compute themselves by comparing CurrentSyncID against the stack's
// own current SyncID (see subscriptionResponse in
// handlers_subscription.go, which does the same comparison for a single
// subscription).
type subscriptionSyncStatus struct {
	Namespace     string `json:"namespace"`
	State         string `json:"state"`
	CurrentSyncID string `json:"current_sync_id"`
	Synced        bool   `json:"synced"`
}

// stackStatusResponse is the body of GET .../stacks/:name/status: the
// stack's own current SyncID, plus every active subscription's own sync
// state against it. Inactive subscriptions (still pending the initial
// action — see Reconciler.handleNewSubscription) are omitted entirely:
// there is no sync state to report for one yet.
type stackStatusResponse struct {
	StackName     string                   `json:"stack_name"`
	SyncID        string                   `json:"sync_id"`
	Subscriptions []subscriptionSyncStatus `json:"subscriptions"`
}

// validateStack checks that s has a name and that every entry in
// DependsOn resolves to an existing Stack — the legacy Postgres model
// enforced neither (no real FK, no app-level check either). Platform/
// Region need no check here: RegisterClusterRoutes always stamps them
// from this instance's own deployment config before validateStack ever
// sees s, never from caller input.
func validateStack(repo *Repository, s Stack) *liberrors.Error {
	if s.Name == "" {
		return liberrors.New(http.StatusBadRequest, "catalog.Stack", "name is required")
	}
	for _, dep := range s.DependsOn {
		if dep.Platform == "" || dep.Region == "" || dep.Name == "" {
			return liberrors.New(http.StatusBadRequest, "catalog.Stack", "depends_on entries require platform, region and name")
		}
		if _, err := repo.GetClusterStack(dep.Platform, dep.Region, dep.Name); err != nil {
			return notFoundOrInternal(err, "catalog.Stack", "depends_on stack %s/%s/%s not found", dep.Platform, dep.Region, dep.Name)
		}
	}
	return nil
}

// RegisterStackRoutes mounts cluster-wide infrastructure Stack CRUD at
// /apis/catalog.example.com/v1/stacks (its own API group — a Stack
// isn't one of internal/rbac's cluster RBAC objects, it just happens to
// share the same trust tier) behind gate (normally
// middleware.SysadminGate). Ported from the legacy Postgres
// "stacks" table; DependsOn replaces that model's separate "dependencies"
// table (see types.go). deploymentPlatform/deploymentRegion are this
// instance's own INFRAPI_APP_PLATFORM/_REGION: every route here addresses
// a stack within that scope alone — there is no platform/region path
// segment or request field, since this instance already knows its own
// and a caller repeating it on every request would only ever be able to
// say the one value that's already true. A DependsOn entry is the one
// place platform/region still appears explicitly: the legacy model let a
// dependency cross platform/region, and that's unchanged.
func RegisterStackRoutes(r gin.IRouter, repo *Repository, gate gin.HandlerFunc, deploymentPlatform, deploymentRegion string) {
	group := r.Group("/apis/"+StackAPI+"/v1", gate)

	group.POST("/stacks", func(c *gin.Context) {
		var s Stack
		if err := c.ShouldBindJSON(&s); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "catalog.CreateStack", ""))
			return
		}
		s.Platform, s.Region = deploymentPlatform, deploymentRegion
		// A stack created with no explicit sync_id gets one minted here
		// rather than kept empty: Reconciler never reconciles a stack
		// whose SyncID is empty (see ensureReconciled), so a kickstarted
		// stack with nothing to reconcile to would otherwise leave every
		// subscriber it ever gains stuck pending until someone remembers
		// to PUT .../sync by hand. A caller that already named an
		// explicit sync_id keeps it.
		if s.SyncID == "" {
			syncID, err := uuid.GenerateUUID()
			if err != nil {
				httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.CreateStack", ""))
				return
			}
			s.SyncID = syncID
		}
		if err := validateStack(repo, s); err != nil {
			httpapi.Fail(c, err)
			return
		}
		if err := repo.PutClusterStack(s); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.CreateStack", ""))
			return
		}
		c.JSON(http.StatusCreated, s)
	})

	// GET /stacks only ever lists this instance's own platform/region:
	// every other route here can only address a stack in that same
	// scope, so listing anything wider would list stacks the rest of
	// this API couldn't individually reach by name anyway.
	group.GET("/stacks", func(c *gin.Context) {
		all, err := repo.ListClusterStacks()
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.ListStacks", ""))
			return
		}
		stacks := make([]Stack, 0, len(all))
		for _, s := range all {
			if s.Platform == deploymentPlatform && s.Region == deploymentRegion {
				stacks = append(stacks, s)
			}
		}
		c.JSON(http.StatusOK, stacks)
	})

	group.GET("/stacks/:name", func(c *gin.Context) {
		s, err := repo.GetClusterStack(deploymentPlatform, deploymentRegion, c.Param("name"))
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "catalog.GetStack", "stack %q not found", c.Param("name")))
			return
		}
		c.JSON(http.StatusOK, s)
	})

	// GET .../status reports every active subscription's sync state
	// against this stack's current SyncID in one call, rather than
	// making a caller list subscriptions per-namespace and compare each
	// one's expected_sync_id by hand.
	group.GET("/stacks/:name/status", func(c *gin.Context) {
		name := c.Param("name")
		stack, err := repo.GetClusterStack(deploymentPlatform, deploymentRegion, name)
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "catalog.StackStatus", "stack %q not found", name))
			return
		}

		subs, err := repo.ListSubscriptionsToStack(name)
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.StackStatus", ""))
			return
		}

		resp := stackStatusResponse{StackName: stack.Name, SyncID: stack.SyncID, Subscriptions: []subscriptionSyncStatus{}}
		for namespace, sub := range subs {
			if !sub.Active {
				continue
			}
			resp.Subscriptions = append(resp.Subscriptions, subscriptionSyncStatus{
				Namespace:     namespace,
				State:         sub.State,
				CurrentSyncID: sub.CurrentSyncID,
				Synced:        sub.CurrentSyncID == stack.SyncID,
			})
		}
		// ListSubscriptionsToStack returns a map, so iteration order is
		// otherwise random — sort by namespace for a stable response.
		sort.Slice(resp.Subscriptions, func(i, j int) bool {
			return resp.Subscriptions[i].Namespace < resp.Subscriptions[j].Namespace
		})
		c.JSON(http.StatusOK, resp)
	})

	group.PUT("/stacks/:name", func(c *gin.Context) {
		name := c.Param("name")
		existing, err := repo.GetClusterStack(deploymentPlatform, deploymentRegion, name)
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "catalog.UpdateStack", "stack %q not found", name))
			return
		}

		var s Stack
		if err := c.ShouldBindJSON(&s); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "catalog.UpdateStack", ""))
			return
		}
		s.Platform, s.Region, s.Name = deploymentPlatform, deploymentRegion, name
		// CanaryNamespaces is pipeline state for an in-progress canary
		// rollout (see Stack), not something this general-purpose update
		// ever touches — only PUT .../sync manages it.
		s.CanaryNamespaces = existing.CanaryNamespaces
		if err := validateStack(repo, s); err != nil {
			httpapi.Fail(c, err)
			return
		}

		if err := repo.PutClusterStack(s); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.UpdateStack", ""))
			return
		}
		c.JSON(http.StatusOK, s)
	})

	// PUT .../sync is the shorthand reconcile trigger. Its optional body
	// names canary_namespaces to start (or replace) a canary rollout —
	// see Stack.CanaryNamespaces — rather than the ordinary full fan-out;
	// an empty/absent body falls back to that ordinary behavior, unless
	// a canary rollout is already pending, in which case it's a release
	// (see the switch below).
	group.PUT("/stacks/:name/sync", func(c *gin.Context) {
		name := c.Param("name")
		s, err := repo.GetClusterStack(deploymentPlatform, deploymentRegion, name)
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "catalog.SyncStack", "stack %q not found", name))
			return
		}

		var req struct {
			CanaryNamespaces []string `json:"canary_namespaces"`
		}
		if c.Request.ContentLength > 0 {
			if err := c.ShouldBindJSON(&req); err != nil {
				httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "catalog.SyncStack", ""))
				return
			}
		}

		switch {
		case len(req.CanaryNamespaces) > 0:
			// Start (or replace) a canary rollout: a fresh target SyncID,
			// but Reconciler only reconciles these namespaces for now —
			// see Stack.CanaryNamespaces and handleStackPut.
			for _, ns := range req.CanaryNamespaces {
				if _, err := repo.GetNamespaceSubscription(ns, name); err != nil {
					httpapi.Fail(c, notFoundOrInternal(err, "catalog.SyncStack", "namespace %q is not subscribed to %q", ns, name))
					return
				}
			}
			syncID, err := uuid.GenerateUUID()
			if err != nil {
				httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.SyncStack", ""))
				return
			}
			s.SyncID = syncID
			s.CanaryNamespaces = req.CanaryNamespaces

		case len(s.CanaryNamespaces) > 0:
			// Release: no canary_namespaces named, and a canary rollout is
			// already pending — fan the SAME SyncID the canary already
			// validated out to everyone else, rather than minting a new
			// one they'd all have to adopt separately.
			s.CanaryNamespaces = nil

		default:
			// Ordinary case, no canary involved at all: a fresh target
			// SyncID for every active subscriber at once, same as always.
			syncID, err := uuid.GenerateUUID()
			if err != nil {
				httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.SyncStack", ""))
				return
			}
			s.SyncID = syncID
		}

		if err := repo.PutClusterStack(s); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.SyncStack", ""))
			return
		}
		c.JSON(http.StatusOK, s)
	})

	group.DELETE("/stacks/:name", func(c *gin.Context) {
		name := c.Param("name")
		if _, err := repo.GetClusterStack(deploymentPlatform, deploymentRegion, name); err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "catalog.DeleteStack", "stack %q not found", name))
			return
		}

		referenced, err := repo.stackIsReferenced(deploymentPlatform, deploymentRegion, name, deploymentPlatform, deploymentRegion)
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.DeleteStack", ""))
			return
		}
		if referenced {
			httpapi.Fail(c, liberrors.New(http.StatusConflict, "catalog.DeleteStack",
				"stack %q is still referenced by another stack's depends_on or by a subscription", name))
			return
		}

		if err := repo.DeleteClusterStack(deploymentPlatform, deploymentRegion, name); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.DeleteStack", ""))
			return
		}
		c.Status(http.StatusNoContent)
	})
}
