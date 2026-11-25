package catalog

import (
	"errors"
	"net/http"

	uuid "github.com/hashicorp/go-uuid"

	"github.com/infrapi/kayra/internal/identity"
	libapi "github.com/infrapi/lib/pkg/api"
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
// (IsLongApiName), that its version is like v1 or v2beta1, that its optional short_name is a single label not
// already used by another registration here, and that every
// entry in DependsOn resolves to an existing ApiRegistration — the
// legacy Postgres model enforced neither (no real FK, no app-level
// check either). Platform/Region need no check here:
// Server always stamps them from this instance's
// own deployment config before validateApiRegistration ever sees reg,
// never from caller input.
func validateApiRegistration(repo *Repository, reg ApiRegistration) *liberrors.Error {
	if reg.Name == "" {
		return liberrors.New(http.StatusBadRequest, "catalog.ApiRegistration", "name is required")
	}
	if !IsLongApiName(reg.Name) {
		return liberrors.New(http.StatusBadRequest, "catalog.ApiRegistration", "name %q must be the api's long name, a lowercase DNS name such as \"compute.infrapi.io\"", reg.Name)
	}
	if err := (libapi.Group{Name: reg.Name, Version: reg.Version}).Validate(); err != nil {
		return liberrors.New(http.StatusBadRequest, "catalog.ApiRegistration", "version %q must be like v1 or v2beta1", reg.Version)
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
	if id := reg.Identity; id != nil {
		forms := 0
		for _, set := range []bool{id.JWKSFrom != "", id.JWKS != nil, len(id.FederatedCredentials) > 0} {
			if set {
				forms++
			}
		}
		if forms != 1 || (id.JWKSFrom != "" && id.JWKSFrom != JWKSFromSpec) {
			return liberrors.New(http.StatusBadRequest, "catalog.ApiRegistration", "identity: one of jwks_from (\"spec\"), jwks or federated_credentials").
				WithSolution(`{"identity": {"jwks_from": "spec"}}: the app serves its public keys at -/jwks.json`)
		}
		if err := identity.CheckCredentials(id.JWKS, id.FederatedCredentials, repo.TrustedIssuer); err != nil {
			e := liberrors.New(http.StatusBadRequest, "catalog.ApiRegistration", "identity.%s", err)
			if errors.Is(err, identity.ErrUntrustedIssuer) {
				e = e.WithSolution("ask Kayra's admin to add it to federation.issuers")
			}
			return e
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

// ensureUID gives reg a uid when it has none: a new registration.
func ensureUID(reg *ApiRegistration) error {
	if reg.UID != "" {
		return nil
	}
	uid, err := uuid.GenerateUUID()
	reg.UID = uid
	return err
}
