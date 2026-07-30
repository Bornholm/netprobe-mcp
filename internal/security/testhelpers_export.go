//go:build !netprobe_no_test_helpers

package security

// SetReleaseForTest attaches a release callback to a SafeTarget. This is
// for unit tests only and must never be called from production code.
//
// The build tag lets production builds (which pass
// `-tags netprobe_no_test_helpers` to `go build`) strip this file.
func SetReleaseForTest(t *SafeTarget, fn func()) { t.release = fn }
