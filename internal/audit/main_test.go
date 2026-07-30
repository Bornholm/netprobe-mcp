package audit

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain guards the audit package against goroutine leaks.
// New() spawns a worker goroutine that drains the event channel;
// tests that do not call Close() will leak it. We allow exactly
// one such goroutine here — the integration test pool — and
// require every test that opens an audit Logger to close it.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreTopFunction("github.com/bornholm/netprobe-mcp/internal/audit.(*Logger).run"),
	)
}
