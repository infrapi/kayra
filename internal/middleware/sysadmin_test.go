package middleware

import "testing"

func TestSysadminGroupForRendersPlatformTemplate(t *testing.T) {
	if got, want := SysadminGroupFor("sandbox"), "sandbox-core-sysadmin"; got != want {
		t.Fatalf("SysadminGroupFor(sandbox) = %q, want %q", got, want)
	}
	if got, want := SysadminGroupFor("prod"), "prod-core-sysadmin"; got != want {
		t.Fatalf("SysadminGroupFor(prod) = %q, want %q", got, want)
	}
}
