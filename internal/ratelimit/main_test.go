package ratelimit

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain guards ratelimit against leaked goroutines, in particular
// the Manager janitor ticker which is started by StartJanitor and
// must terminate when its context is cancelled. Tests that exercise
// the janitor MUST cancel the context; this verification catches
// any drift.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
	)
}
