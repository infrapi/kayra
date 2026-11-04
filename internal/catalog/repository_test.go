package catalog

import (
	"testing"

	"github.com/infrapi/kayra/internal/store"
)

func TestClusterStackRoundTripListDelete(t *testing.T) {
	repo := newTestRepo(t)

	vault := Stack{Name: "vault", Platform: testDeployPlatform, Region: testDeployRegion, Active: true}
	pki := Stack{
		Name: "pki", Platform: testDeployPlatform, Region: testDeployRegion, Active: true,
		DependsOn: []StackRef{{Platform: testDeployPlatform, Region: testDeployRegion, Name: "vault"}},
	}
	if err := repo.PutClusterStack(vault); err != nil {
		t.Fatalf("PutClusterStack(vault): %v", err)
	}
	if err := repo.PutClusterStack(pki); err != nil {
		t.Fatalf("PutClusterStack(pki): %v", err)
	}

	got, err := repo.GetClusterStack(testDeployPlatform, testDeployRegion, "pki")
	if err != nil {
		t.Fatalf("GetClusterStack: %v", err)
	}
	if len(got.DependsOn) != 1 || got.DependsOn[0].Name != "vault" {
		t.Fatalf("GetClusterStack(pki).DependsOn = %v, want [vault]", got.DependsOn)
	}

	stacks, err := repo.ListClusterStacks()
	if err != nil {
		t.Fatalf("ListClusterStacks: %v", err)
	}
	if len(stacks) != 2 {
		t.Fatalf("ListClusterStacks = %v, want 2 entries", stacks)
	}

	// vault is referenced by pki's DependsOn: must not be deletable...
	// (the handler enforces this; here we just verify the detection.)
	referenced, err := repo.stackIsReferenced(testDeployPlatform, testDeployRegion, "vault", testDeployPlatform, testDeployRegion)
	if err != nil {
		t.Fatalf("stackIsReferenced: %v", err)
	}
	if !referenced {
		t.Fatalf("stackIsReferenced(vault) = false, want true (pki depends on it)")
	}

	// ...but pki itself, which nothing depends on, is not referenced.
	referenced, err = repo.stackIsReferenced(testDeployPlatform, testDeployRegion, "pki", testDeployPlatform, testDeployRegion)
	if err != nil {
		t.Fatalf("stackIsReferenced: %v", err)
	}
	if referenced {
		t.Fatalf("stackIsReferenced(pki) = true, want false")
	}

	if err := repo.DeleteClusterStack(testDeployPlatform, testDeployRegion, "pki"); err != nil {
		t.Fatalf("DeleteClusterStack: %v", err)
	}
	if _, err := repo.GetClusterStack(testDeployPlatform, testDeployRegion, "pki"); err != store.ErrNotFound {
		t.Fatalf("GetClusterStack after delete = %v, want ErrNotFound", err)
	}
}

func TestStackIsReferencedBySubscription(t *testing.T) {
	repo := newTestRepo(t)

	stack := Stack{Name: "vault", Platform: testDeployPlatform, Region: testDeployRegion, Active: true}
	if err := repo.PutClusterStack(stack); err != nil {
		t.Fatalf("PutClusterStack: %v", err)
	}

	referenced, err := repo.stackIsReferenced(testDeployPlatform, testDeployRegion, "vault", testDeployPlatform, testDeployRegion)
	if err != nil {
		t.Fatalf("stackIsReferenced: %v", err)
	}
	if referenced {
		t.Fatalf("stackIsReferenced = true before any subscription exists")
	}

	sub := Subscription{StackName: "vault", Active: true, State: SubscriptionStateInit}
	if err := repo.PutNamespaceSubscription("myns", sub); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}

	referenced, err = repo.stackIsReferenced(testDeployPlatform, testDeployRegion, "vault", testDeployPlatform, testDeployRegion)
	if err != nil {
		t.Fatalf("stackIsReferenced: %v", err)
	}
	if !referenced {
		t.Fatalf("stackIsReferenced = false, want true (myns subscribes to it)")
	}
}

// TestStackIsReferencedIgnoresSubscriptionsOutsideDeploymentScope confirms
// a subscription (which carries no platform/region) is only ever
// consulted when checking a stack that's actually in this deployment's
// own platform/region — it is meaningless, and must be skipped, for a
// stack anywhere else.
func TestStackIsReferencedIgnoresSubscriptionsOutsideDeploymentScope(t *testing.T) {
	repo := newTestRepo(t)

	stack := Stack{Name: "vault", Platform: "other-platform", Region: "other-region", Active: true}
	if err := repo.PutClusterStack(stack); err != nil {
		t.Fatalf("PutClusterStack: %v", err)
	}
	sub := Subscription{StackName: "vault", Active: true, State: SubscriptionStateInit}
	if err := repo.PutNamespaceSubscription("myns", sub); err != nil {
		t.Fatalf("PutNamespaceSubscription: %v", err)
	}

	referenced, err := repo.stackIsReferenced("other-platform", "other-region", "vault", testDeployPlatform, testDeployRegion)
	if err != nil {
		t.Fatalf("stackIsReferenced: %v", err)
	}
	if referenced {
		t.Fatalf("stackIsReferenced = true, want false (subscription can only ever mean the deployment's own platform/region)")
	}
}

func TestNamespaceRoundTripAndListAll(t *testing.T) {
	repo := newTestRepo(t)

	n1 := Namespace{Name: "myns", Active: true}
	n2 := Namespace{Name: "otherns", Active: false}
	if err := repo.PutNamespace(n1); err != nil {
		t.Fatalf("PutNamespace: %v", err)
	}
	if err := repo.PutNamespace(n2); err != nil {
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

	if err := repo.PutNamespace(Namespace{Name: "myns", Active: true}); err != nil {
		t.Fatalf("PutNamespace: %v", err)
	}
	if err := repo.PutNamespaceSubscription("myns", Subscription{StackName: "vault"}); err != nil {
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

	sub := Subscription{StackName: "vault", Active: true, State: SubscriptionStateSuccess}
	if err := repo.PutNamespaceSubscription(ns, sub); err != nil {
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
