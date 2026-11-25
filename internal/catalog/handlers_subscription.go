package catalog

import (
	"net/http"

	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

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
	ApiName        string `json:"api"`
	Active         bool   `json:"active"`
	State          string `json:"state"`
	CurrentSyncID  string `json:"current_sync_id"`
	ExpectedSyncID string `json:"expected_sync_id"`
	// Synced is CurrentSyncID == ExpectedSyncID for an active
	// subscription — false means the api owner has a sync to run. It
	// never affects access: an active subscription works either way.
	// Same name and meaning as GET .../apiregistrations/:name/status.
	Synced bool `json:"synced"`
	store.Timestamps
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
		Timestamps:    sub.Timestamps,
	}
	if reg, err := repo.GetClusterApiRegistration(deploymentPlatform, deploymentRegion, sub.ApiName); err == nil {
		resp.ExpectedSyncID = reg.SyncID
	}
	resp.Synced = sub.Active && resp.CurrentSyncID == resp.ExpectedSyncID
	return resp
}

// validateSubscription checks that sub's State is one of the four
// allowed values, and that the api registration it names exists in
// this deployment's own platform+region — the legacy Postgres model
// enforced neither existence (no real FK) nor a real check beyond
// string parsing on State.
func validateSubscription(repo *Repository, sub Subscription, deploymentPlatform, deploymentRegion string) *liberrors.Error {
	if sub.ApiName == "" {
		return liberrors.New(http.StatusBadRequest, "catalog.Subscription", "api is required")
	}
	if !ValidSubscriptionState(sub.State) {
		return liberrors.New(http.StatusBadRequest, "catalog.Subscription", "state %q is not one of init, success, error", sub.State)
	}
	if !IsLongApiName(sub.ApiName) {
		msg := "api %q must be the api's long name, e.g. \"compute.infrapi.io\""
		args := []any{sub.ApiName}
		if reg, found, err := repo.findByShortName(deploymentPlatform, deploymentRegion, sub.ApiName); err == nil && found {
			msg = "api %q is a short name: subscribe with its long name %q"
			args = append(args, reg.Name)
		}
		return liberrors.New(http.StatusBadRequest, "catalog.Subscription", msg, args...)
	}
	if _, err := repo.GetClusterApiRegistration(deploymentPlatform, deploymentRegion, sub.ApiName); err != nil {
		return notFoundOrInternal(err, "catalog.Subscription", "api registration %q not found in %s/%s", sub.ApiName, deploymentPlatform, deploymentRegion)
	}
	return nil
}
