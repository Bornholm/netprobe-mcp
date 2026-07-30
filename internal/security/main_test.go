package security

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain guards the security pipeline against goroutine leaks.
// The LRU eviction goroutines in resolver.go and the SafeDialer
// Control callbacks must not outlive the test process.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
	)
}
