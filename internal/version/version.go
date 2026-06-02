// Package version exposes the build-time version string of postern.
//
// The Version value is overridden at release time via ldflags, e.g.:
//
//	go build -ldflags "-X github.com/mmartinez/postern/internal/version.Version=v0.1.0"
//
// During development builds (and in tests) it falls back to "dev".
package version

// Version is the semantic version of this build. Goreleaser sets it via ldflags
// at release time; otherwise it stays at the development default.
var Version = "dev"
