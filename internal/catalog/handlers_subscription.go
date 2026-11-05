package catalog

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/rbac"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// subscriptionCreateRequest is the request body for creating a
// subscription: api_name is the only thing a caller controls. Active
// and State are computed, deliberately absent here — a subscription is
// always created disabled/init, and can only ever be moved to
// active/success by Repository.ActivateSubscription (an internal-only
// path no HTTP route exposes).
type subscriptionCreateRequest struct {
	ApiName string `json:"api_name"`
}

// subscriptionResponse is what every subscription handler returns.
// current_sync_id is Subscription.CurrentSyncID, the value persisted on
// the subscription itself; expected_sync_id is never stored there at all
// — it's the referenced registration's own, current SyncID, read fresh
// on every response (see buildSubscriptionResponse), so a caller can
// tell "reconciled" (the two match) from "reconcile pending" (they
// don't) without a second request, and it's never stale between
// Reconciler runs.
// Neither field is omitempty: both are always reported, "" when there's
// nothing to report, rather than silently missing from the body.
type subscriptionResponse struct {
	ApiName        string `json:"api_name"`
	Active         bool   `json:"active"`
	State          string `json:"state"`
	CurrentSyncID  string `json:"current_sync_id"`
	ExpectedSyncID string `json:"expected_sync_id"`
}

// buildSubscriptionResponse reads sub's api registration for its
// current SyncID — absent (registration not found) leaves
// ExpectedSyncID empty rather than failing the response; GET/POST/PUT
// on a subscription aren't where a missing registration should surface
// as an error.
func buildSubscriptionResponse(repo *Repository, sub Subscription, deploymentPlatform, deploymentRegion string) subscriptionResponse {
	resp := subscriptionResponse{
		ApiName:       sub.ApiName,
		Active:        sub.Active,
		State:         sub.State,
		CurrentSyncID: sub.CurrentSyncID,
	}
	if reg, err := repo.GetClusterApiRegistration(deploymentPlatform, deploymentRegion, sub.ApiName); err == nil {
		resp.ExpectedSyncID = reg.SyncID
	}
	return resp
}

// validateSubscription checks that sub's State is one of the four
// allowed values, and that the api registration it names exists in
// this deployment's own platform+region — the legacy Postgres model
// enforced neither existence (no real FK) nor a real check beyond
// string parsing on State.
func validateSubscription(repo *Repository, sub Subscription, deploymentPlatform, deploymentRegion string) *liberrors.Error {
	if sub.ApiName == "" {
		return liberrors.New(http.StatusBadRequest, "catalog.Subscription", "api_name is required")
	}
	if !ValidSubscriptionState(sub.State) {
		return liberrors.New(http.StatusBadRequest, "catalog.Subscription", "state %q is not one of init, success, error, undef", sub.State)
	}
	if _, err := repo.GetClusterApiRegistration(deploymentPlatform, deploymentRegion, sub.ApiName); err != nil {
		return notFoundOrInternal(err, "catalog.Subscription", "api registration %q not found in %s/%s", sub.ApiName, deploymentPlatform, deploymentRegion)
	}
	return nil
}

// RegisterNamespaceRoutes mounts namespace-scoped Subscription CRUD —
// the legacy model's tenant↔api registration link — at
// /apis/subscription.example.com/v1/namespaces/:namespace/
// subscriptions{,/:api{,/sync}}, its own API group exactly like
// internal/rbac's own groups/roles/rolebindings routes are
// authorization.example.com's, behind gate (normally
// middleware.Authenticator) followed by
// rbac.RequireClusterRBAC(rbacRepo, rbac.SubscriptionAPI,
// "subscriptions"|"subscriptions/sync", verb): a Subscription is gated by
// the exact same cluster RBAC check as every RBAC object internal/rbac
// manages, not a separate permission, so it reuses that check directly
// rather than re-implementing it, just against SubscriptionAPI instead
// of AuthorizationAPI. Note :api here (the subscribed-to
// ApiRegistration's name, e.g. "vault") is an entirely different thing
// from SubscriptionAPI — the latter is Kayra's own fixed RBAC API URN
// for this API group, the former is whichever registration a given
// subscription targets. Ported from the legacy Postgres "subscriptions"
// table. deploymentPlatform/deploymentRegion are this instance's own
// INFRAPI_APP_PLATFORM/_REGION: unlike the legacy model (one Postgres DB
// serving every platform/region), this deployment only ever runs in one,
// so a subscription names a registration by name alone — there is no
// second one it could mean.
func RegisterNamespaceRoutes(r gin.IRouter, repo *Repository, rbacRepo *rbac.Repository, gate gin.HandlerFunc, deploymentPlatform, deploymentRegion string) {
	group := r.Group("/apis/"+rbac.SubscriptionAPI+"/v1/namespaces/:namespace", gate)

	group.POST("/subscriptions", rbac.RequireClusterRBAC(rbacRepo, rbac.SubscriptionAPI, "subscriptions", "create"), func(c *gin.Context) {
		namespace := c.Param("namespace")

		var req subscriptionCreateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, "catalog.CreateSubscription", ""))
			return
		}

		sub := Subscription{ApiName: req.ApiName, Active: false, State: SubscriptionStateInit}
		if err := validateSubscription(repo, sub, deploymentPlatform, deploymentRegion); err != nil {
			httpapi.Fail(c, err)
			return
		}

		if err := repo.PutNamespaceSubscription(namespace, sub); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.CreateSubscription", ""))
			return
		}
		c.JSON(http.StatusCreated, buildSubscriptionResponse(repo, sub, deploymentPlatform, deploymentRegion))
	})

	group.GET("/subscriptions", rbac.RequireClusterRBAC(rbacRepo, rbac.SubscriptionAPI, "subscriptions", "list"), func(c *gin.Context) {
		subs, err := repo.ListNamespaceSubscriptions(c.Param("namespace"))
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.ListSubscriptions", ""))
			return
		}
		out := make([]subscriptionResponse, len(subs))
		for i, sub := range subs {
			out[i] = buildSubscriptionResponse(repo, sub, deploymentPlatform, deploymentRegion)
		}
		c.JSON(http.StatusOK, out)
	})

	group.GET("/subscriptions/:api", rbac.RequireClusterRBAC(rbacRepo, rbac.SubscriptionAPI, "subscriptions", "get"), func(c *gin.Context) {
		namespace, api := c.Param("namespace"), c.Param("api")
		sub, err := repo.GetNamespaceSubscription(namespace, api)
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "catalog.GetSubscription", "subscription to %q not found", api))
			return
		}
		c.JSON(http.StatusOK, buildSubscriptionResponse(repo, sub, deploymentPlatform, deploymentRegion))
	})

	// PUT is a no-op confirmation, kept for API shape compatibility: api
	// (the path segment) is the only thing that ever identified a
	// subscription, and Active/State are computed (see
	// Repository.ActivateSubscription) — there is nothing left in the
	// body a caller could legitimately change.
	group.PUT("/subscriptions/:api", rbac.RequireClusterRBAC(rbacRepo, rbac.SubscriptionAPI, "subscriptions", "update"), func(c *gin.Context) {
		namespace, api := c.Param("namespace"), c.Param("api")
		sub, err := repo.GetNamespaceSubscription(namespace, api)
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "catalog.UpdateSubscription", "subscription to %q not found", api))
			return
		}
		c.JSON(http.StatusOK, buildSubscriptionResponse(repo, sub, deploymentPlatform, deploymentRegion))
	})

	// PUT .../sync force-resets CurrentSyncID to empty, nothing else —
	// the subscription-level mirror of /apiregistrations/:name/sync.
	// Reconciler reacts to the resulting write exactly like any other
	// subscription change: CurrentSyncID no longer matches the
	// registration's own SyncID, so it reconciles again, without having
	// to wait for the registration itself to move on.
	group.PUT("/subscriptions/:api/sync", rbac.RequireClusterRBAC(rbacRepo, rbac.SubscriptionAPI, "subscriptions/sync", "patch"), func(c *gin.Context) {
		namespace, api := c.Param("namespace"), c.Param("api")
		sub, err := repo.GetNamespaceSubscription(namespace, api)
		if err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "catalog.SyncSubscription", "subscription to %q not found", api))
			return
		}

		if err := repo.SetSubscriptionSyncID(namespace, api, ""); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.SyncSubscription", ""))
			return
		}
		sub.CurrentSyncID = ""

		c.JSON(http.StatusOK, buildSubscriptionResponse(repo, sub, deploymentPlatform, deploymentRegion))
	})

	group.DELETE("/subscriptions/:api", rbac.RequireClusterRBAC(rbacRepo, rbac.SubscriptionAPI, "subscriptions", "delete"), func(c *gin.Context) {
		namespace, api := c.Param("namespace"), c.Param("api")
		if _, err := repo.GetNamespaceSubscription(namespace, api); err != nil {
			httpapi.Fail(c, notFoundOrInternal(err, "catalog.DeleteSubscription", "subscription to %q not found", api))
			return
		}
		if err := repo.DeleteNamespaceSubscription(namespace, api); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "catalog.DeleteSubscription", ""))
			return
		}
		c.Status(http.StatusNoContent)
	})
}
