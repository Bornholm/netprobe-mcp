package icmp

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain guards icmp against goroutine leaks. The raw-socket
// multiplexer reader (started on first raw-mode use) MUST exit when
// the context passed to Run is cancelled; the tests that exercise
// it must use t.Context() so the cancellation propagates.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
	)
}
