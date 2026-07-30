// Package build exposes build-time identifiers injected via -ldflags
// during release builds (see .goreleaser.yaml). The variables default
// to "dev" so the package compiles cleanly without linker overrides,
// and a `go run` invocation always reports a sensible version.
package build

// These values are overwritten at link time by:
//
//	-X 'github.com/bornholm/netprobe-mcp/internal/build.Version=...'
//	-X 'github.com/bornholm/netprobe-mcp/internal/build.LongVersion=...'
//
// Defaults are chosen so `go run ./cmd/netprobe-mcp -version` reports
// "dev" rather than crashing.
var (
	// Version is the short semver (e.g. "0.1.0"). Used in the
	// MCP implementation descriptor and CLI banner.
	Version = "dev"

	// LongVersion is the human-readable build identifier (e.g.
	// "0.1.0 (abc1234)" or "dev (unknown)"). Surfaced in --version
	// output and crash logs.
	LongVersion = "dev (unknown)"
)
