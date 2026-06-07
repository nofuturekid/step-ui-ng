package app

import "runtime/debug"

// defaultVersion is the development fallback that Version holds when no ldflags
// value was stamped. It MUST match the literal assigned to Version in server.go;
// BuildInfo uses it to decide whether to enrich the version with VCS data.
const defaultVersion = "0.1.1"

// BuildInfo returns a human-readable version string for logs and the -version
// flag. An explicit ldflags value (a release tag) always wins and is returned
// verbatim. When Version is still the development default, BuildInfo enriches it
// with the VCS revision from the embedded build info (short commit, plus "-dirty"
// when the working tree was modified) so dev builds are identifiable. VCS data
// may be absent (e.g. under `go test`), in which case the bare default is
// returned. See ADR-0013.
func BuildInfo() string {
	if Version != defaultVersion {
		return Version
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return Version
	}

	var revision string
	var modified bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if revision == "" {
		return Version
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	out := Version + "-" + revision
	if modified {
		out += "-dirty"
	}
	return out
}
