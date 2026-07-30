package build

import "testing"

// TestDefaults asserts the package compiles and reports "dev" when
// no ldflags are provided. We do not override Version/LongVersion
// because that would mutate package-level state across tests in
// other packages using -count > 1.
func TestDefaults(t *testing.T) {
	if Version != "dev" {
		t.Fatalf("Version = %q, want default %q", Version, "dev")
	}
	if LongVersion != "dev (unknown)" {
		t.Fatalf("LongVersion = %q, want default %q", LongVersion, "dev (unknown)")
	}
}
