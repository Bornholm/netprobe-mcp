package probe

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain guards the probe package against goroutine leaks. The TCP
// and HTTP subtests open loopback listeners that, if not closed
// properly, would surface here as long-lived Accept goroutines.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreTopFunction("net.(*TCPListener).Accept"),
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
	)
}
