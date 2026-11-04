package clicontext

import (
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFrom_missingFileReturnsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")

	f, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if f.CurrentContext != "" {
		t.Errorf("CurrentContext = %q, want empty", f.CurrentContext)
	}
	if len(f.Contexts) != 0 {
		t.Errorf("Contexts = %v, want empty", f.Contexts)
	}
}

func TestSaveTo_roundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kayra", "config")

	f := &File{Contexts: map[string]Context{}}
	f.SetContext("okta", Context{
		Server:    "https://kayra.example.com",
		Provider:  "okta",
		Token:     "tok-1",
		TokenType: "Bearer",
		Expiry:    time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	})

	if err := f.SaveTo(path); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}

	got, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if got.CurrentContext != "okta" {
		t.Errorf("CurrentContext = %q, want %q", got.CurrentContext, "okta")
	}
	ctx, ok := got.Contexts["okta"]
	if !ok {
		t.Fatalf("Contexts[okta] missing: %v", got.Contexts)
	}
	if ctx.Token != "tok-1" || ctx.Server != "https://kayra.example.com" {
		t.Errorf("Contexts[okta] = %+v, want token tok-1 and matching server", ctx)
	}
}

func TestSetContext_switchesCurrent(t *testing.T) {
	f := &File{Contexts: map[string]Context{}}
	f.SetContext("a", Context{Token: "tok-a"})
	f.SetContext("b", Context{Token: "tok-b"})

	if f.CurrentContext != "b" {
		t.Errorf("CurrentContext = %q, want %q", f.CurrentContext, "b")
	}
	if len(f.Contexts) != 2 {
		t.Errorf("Contexts = %v, want 2 entries", f.Contexts)
	}
}

func TestUse(t *testing.T) {
	f := &File{Contexts: map[string]Context{"a": {Token: "tok-a"}, "b": {Token: "tok-b"}}}
	f.CurrentContext = "a"

	if err := f.Use("b"); err != nil {
		t.Fatalf("Use: %v", err)
	}
	if f.CurrentContext != "b" {
		t.Errorf("CurrentContext = %q, want %q", f.CurrentContext, "b")
	}

	if err := f.Use("missing"); err == nil {
		t.Error("Use(missing) = nil error, want error")
	}
}

func TestDelete(t *testing.T) {
	f := &File{Contexts: map[string]Context{"a": {Token: "tok-a"}}}
	f.CurrentContext = "a"

	if err := f.Delete("a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if f.CurrentContext != "" {
		t.Errorf("CurrentContext = %q, want empty after deleting current", f.CurrentContext)
	}
	if _, ok := f.Contexts["a"]; ok {
		t.Error("Contexts[a] still present after Delete")
	}

	if err := f.Delete("a"); err == nil {
		t.Error("Delete(a) twice = nil error, want error")
	}
}

func TestCurrent(t *testing.T) {
	f := &File{Contexts: map[string]Context{}}
	if _, _, err := f.Current(); err == nil {
		t.Error("Current() on empty File = nil error, want error")
	}

	f.SetContext("a", Context{Token: "tok-a"})
	name, ctx, err := f.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if name != "a" || ctx.Token != "tok-a" {
		t.Errorf("Current() = (%q, %+v), want (a, token tok-a)", name, ctx)
	}
}

func TestNames_sorted(t *testing.T) {
	f := &File{Contexts: map[string]Context{"charlie": {}, "alpha": {}, "bravo": {}}}

	got := f.Names()
	want := []string{"alpha", "bravo", "charlie"}
	if len(got) != len(want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Names()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestPath_envVarOverride(t *testing.T) {
	t.Setenv(contextFileEnvVar, "/custom/path/config")
	got, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if got != "/custom/path/config" {
		t.Errorf("Path() = %q, want %q", got, "/custom/path/config")
	}
}

func TestPath_defaultsUnderConfigDir(t *testing.T) {
	t.Setenv(contextFileEnvVar, "")
	t.Setenv("XDG_CONFIG_HOME", "/home/x/.config")

	got, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	want := filepath.Join("/home/x/.config", "kayra", "config")
	if got != want {
		t.Errorf("Path() = %q, want %q", got, want)
	}
}
