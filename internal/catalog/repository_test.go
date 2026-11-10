package catalog

import (
	"testing"

	"github.com/infrapi/kayra/internal/store"
)

func TestClusterApiRegistrationRoundTripListDelete(t *testing.T) {
	repo := newTestRepo(t)

	vault := ApiRegistration{Name: "vault", Platform: testDeployPlatform, Region: testDeployRegion, Active: true}
	pki := ApiRegistration{
		Name: "pki", Platform: testDeployPlatform, Region: testDeployRegion, Active: true,
		DependsOn: []ApiRegistrationRef{{Platform: testDeployPlatform, Region: testDeployRegion, Name: "vault"}},
	}
	if err := repo.PutClusterApiRegistration(&vault); err != nil {
		t.Fatalf("PutClusterApiRegistration(vault): %v", err)
	}
	if err := repo.PutClusterApiRegistration(&pki); err != nil {
		t.Fatalf("PutClusterApiRegistration(pki): %v", err)
	}

	got, err := repo.GetClusterApiRegistration(testDeployPlatform, testDeployRegion, "pki")
	if err != nil {
		t.Fatalf("GetClusterApiRegistration: %v", err)
	}
	if len(got.DependsOn) != 1 || got.DependsOn[0].Name != "vault" {
		t.Fatalf("GetClusterApiRegistration(pki).DependsOn = %v, want [vault]", got.DependsOn)
	}

	regs, err := repo.ListClusterApiRegistrations()
	if err != nil {
		t.Fatalf("ListClusterApiRegistrations: %v", err)
	}
	if len(regs) != 2 {
		t.Fatalf("ListClusterApiRegistrations = %v, want 2 entries", regs)
	}

	// vault is referenced by pki's DependsOn: must not be deletable...
	// (the handler enforces this; here we just verify the detection.)
	referenced, err := repo.apiRegistrationIsReferenced(testDeployPlatform, testDeployRegion, "vault", testDeployPlatform, testDeployRegion)
	if err != nil {
		t.Fatalf("apiRegistrationIsReferenced: %v", err)
	}
	if !referenced {
		t.Fatalf("apiRegistrationIsReferenced(vault) = false, want true (pki depends on it)")
	}

	// ...but pki itself, which nothing depends on, is not referenced.
	referenced, err = repo.apiRegistrationIsReferenced(testDeployPlatform, testDeployRegion, "pki", testDeployPlatform, testDeployRegion)
	if err != nil {
		t.Fatalf("apiRegistrationIsReferenced: %v", err)
	}
	if referenced {
		t.Fatalf("apiRegistrationIsReferenced(pki) = true, want false")
	}

	if err := repo.DeleteClusterApiRegistration(testDeployPlatform, testDeployRegion, "pki"); err != nil {
		t.Fatalf("DeleteClusterApiRegistration: %v", err)
	}
	if _, err := repo.GetClusterApiRegistration(testDeployPlatform, testDeployRegion, "pki"); err != store.ErrNotFound {
		t.Fatalf("GetClusterApiRegistration after delete = %v, want ErrNotFound", err)
	}
}

func TestApiRegistrationIsReferencedBySubscription(t *testing.T) {
	repo := newTestRepo(t)

	reg := ApiRegistration{Name: "vault", Platform: testDeployPlatform, Region: testDeployRegion, Active: true}
	if err := repo.PutClusterApiRegistration(&reg); err != nil {
		t.Fatalf("PutClusterApiRegistration: %v", err)
	}

	referenced, err := repo.apiRegistrationIsReferenced(testDeployPlatform, testDeployRegion, "vault", testDeployPlatform, testDeployRegion)
	if err != nil {
		t.Fatalf("apiRegistrationIsReferenced: %v", err)
	}
	if referenced {
		t.Fatalf("apiRegistrationIsReferenced = true before any subscription exists")
	}

	sub := Subscription{ApiName: "vault", Active: true, State: SubscriptionStateInit}
	if err := repo.PutNamespaceSubscription("myns", &sub); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}

	referenced, err = repo.apiRegistrationIsReferenced(testDeployPlatform, testDeployRegion, "vault", testDeployPlatform, testDeployRegion)
	if err != nil {
		t.Fatalf("apiRegistrationIsReferenced: %v", err)
	}
	if !referenced {
		t.Fatalf("apiRegistrationIsReferenced = false, want true (myns subscribes to it)")
	}
}

// TestApiRegistrationIsReferencedIgnoresSubscriptionsOutsideDeploymentScope confirms
// a subscription (which carries no platform/region) is only ever
// consulted when checking a reg that's actually in this deployment's
// own platform/region — it is meaningless, and must be skipped, for a
// reg anywhere else.
func TestApiRegistrationIsReferencedIgnoresSubscriptionsOutsideDeploymentScope(t *testing.T) {
	repo := newTestRepo(t)

	reg := ApiRegistration{Name: "vault", Platform: "other-platform", Region: "other-region", Active: true}
	if err := repo.PutClusterApiRegistration(&reg); err != nil {
		t.Fatalf("PutClusterApiRegistration: %v", err)
	}
	sub := Subscription{ApiName: "vault", Active: true, State: SubscriptionStateInit}
	if err := repo.PutNamespaceSubscription("myns", &sub); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}

	referenced, err := repo.apiRegistrationIsReferenced("other-platform", "other-region", "vault", testDeployPlatform, testDeployRegion)
	if err != nil {
		t.Fatalf("apiRegistrationIsReferenced: %v", err)
	}
	if referenced {
		t.Fatalf("apiRegistrationIsReferenced = true, want false (subscription can only ever mean the deployment's own platform/region)")
	}
}

func TestNamespaceRoundTripAndListAll(t *testing.T) {
	repo := newTestRepo(t)

	n1 := Namespace{Name: "myns", Active: true}
	n2 := Namespace{Name: "otherns", Active: false}
	if err := repo.PutNamespace(&n1); err != nil {
		t.Fatalf("PutNamespace: %v", err)
	}
	if err := repo.PutNamespace(&n2); err != nil {
		t.Fatalf("PutNamespace: %v", err)
	}

	got, err := repo.GetNamespace("myns")
	if err != nil {
		t.Fatalf("GetNamespace: %v", err)
	}
	if !got.Active {
		t.Fatalf("GetNamespace = %+v", got)
	}

	all, err := repo.ListNamespaces()
	if err != nil {
		t.Fatalf("ListNamespaces: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("ListNamespaces = %v, want 2 entries", all)
	}

	if err := repo.DeleteNamespace("myns"); err != nil {
		t.Fatalf("DeleteNamespace: %v", err)
	}
	if _, err := repo.GetNamespace("myns"); err != store.ErrNotFound {
		t.Fatalf("GetNamespace after delete = %v, want ErrNotFound", err)
	}
}

// TestListNamespacesDoesNotLeakSubscriptionResources confirms the scan
// behind ListNamespaces matches only a namespace's own config record,
// not its subscriptions — which also happen to end in "/config".
func TestListNamespacesDoesNotLeakSubscriptionResources(t *testing.T) {
	repo := newTestRepo(t)

	if err := repo.PutNamespace(&Namespace{Name: "myns", Active: true}); err != nil {
		t.Fatalf("PutNamespace: %v", err)
	}
	if err := repo.PutNamespaceSubscription("myns", &Subscription{ApiName: "vault"}); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}

	all, err := repo.ListNamespaces()
	if err != nil {
		t.Fatalf("ListNamespaces: %v", err)
	}
	if len(all) != 1 || all[0].Name != "myns" {
		t.Fatalf("ListNamespaces = %v, want exactly [myns]", all)
	}
}

func TestNamespaceSubscriptionRoundTripListDelete(t *testing.T) {
	repo := newTestRepo(t)
	ns := "myns"

	sub := Subscription{ApiName: "vault", Active: true, State: SubscriptionStateSuccess}
	if err := repo.PutNamespaceSubscription(ns, &sub); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}

	got, err := repo.GetNamespaceSubscription(ns, "vault")
	if err != nil {
		t.Fatalf("GetNamespaceSubscription: %v", err)
	}
	if got.State != SubscriptionStateSuccess {
		t.Fatalf("GetNamespaceSubscription.State = %q, want success", got.State)
	}

	subs, err := repo.ListNamespaceSubscriptions(ns)
	if err != nil {
		t.Fatalf("ListNamespaceSubscriptions: %v", err)
	}
	if len(subs) != 1 {
		t.Fatalf("ListNamespaceSubscriptions = %v, want 1 entry", subs)
	}

	if err := repo.DeleteNamespaceSubscription(ns, "vault"); err != nil {
		t.Fatalf("DeleteNamespaceSubscription: %v", err)
	}
	if _, err := repo.GetNamespaceSubscription(ns, "vault"); err != store.ErrNotFound {
		t.Fatalf("GetNamespaceSubscription after delete = %v, want ErrNotFound", err)
	}
}
