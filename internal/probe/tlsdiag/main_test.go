package tlsdiag

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain verifies that no goroutines leak out of tlsdiag tests.
// The TLS subtests launch their own accept loops via helpers_test.go
// (startTLSServer / startTLS13OnlyServer); any listener that fails
// to close shows up here as a goroutine that never exits.
//
// Top-function ignores are limited to goroutines that are
// deliberately left running by design (the multiplexed raw-ICMP
// socket in icmp.Prober lives in a sibling package and is not
// exercised here) or by Go's runtime (the poll wait on idle
// sockets).
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreTopFunction("net.(*TCPListener).Accept"),
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
	)
}
