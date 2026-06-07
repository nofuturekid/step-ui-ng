package app

import (
	"strings"
	"testing"
)

// An explicit ldflags value (a release tag) is returned verbatim: BuildInfo must
// never mangle a stamped version. This is the contract release.yml relies on
// (-X ...app.Version=<tag>) and what `stepui -version` / /healthz surface.
func TestBuildInfoReturnsStampedVersion(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })

	Version = "v9.9.9"
	if got := BuildInfo(); got != "v9.9.9" {
		t.Fatalf("BuildInfo() = %q, want v9.9.9 (a stamped ldflags value must win verbatim)", got)
	}
}

// At the development default, BuildInfo must be non-empty and not panic. We do
// NOT assert specific VCS data: it is absent under `go test` (no main module
// build info), so the contract is only "usable, never empty, starts with the
// default".
func TestBuildInfoDefaultIsNonEmpty(t *testing.T) {
	if Version != defaultVersion {
		t.Skipf("Version was stamped to %q; default path not exercised", Version)
	}
	got := BuildInfo()
	if got == "" {
		t.Fatal("BuildInfo() is empty at the default version")
	}
	if !strings.HasPrefix(got, defaultVersion) {
		t.Fatalf("BuildInfo() = %q, want it to start with the default %q", got, defaultVersion)
	}
}
