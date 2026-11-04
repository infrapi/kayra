package apiserver

import (
	"testing"

	gconfig "github.com/infrapi/kayra/internal/config"
)

// TestExampleYAMLBuildsCleanly confirms the real examples/kayra.yaml
// (not a hand-built test fixture) builds a full engine without panicking
// — in particular that oauth2broker.RegisterRoutes tolerates a provider
// with no remote.oauth2 configured.
func TestExampleYAMLBuildsCleanly(t *testing.T) {
	cfg, err := gconfig.Load("../../examples/kayra.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// kayra.yaml's own database.main is a real etcd cluster that
	// doesn't exist here — swap in a local dir so Build can actually
	// open a store.
	cfg.Database = map[string]gconfig.DatabaseBackend{
		"dev": {Local: &gconfig.LocalConfig{Path: t.TempDir()}},
	}
	// authorizations.dev.local.path is authored relative to the repo
	// root (where `kayra serve` is actually run from), not this
	// package's own directory — resolve it the same way for the test.
	devAuthz := cfg.Authorizations["dev"]
	devAuthz.Local.Path = "../../" + devAuthz.Local.Path
	cfg.Authorizations["dev"] = devAuthz

	if _, err := Build(testAppConfig(), cfg); err != nil {
		t.Fatalf("Build: %v", err)
	}
}
