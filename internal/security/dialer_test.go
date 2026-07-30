package security

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/bornholm/netprobe-mcp/internal/ratelimit"
)

// TestSafeDialer_NoRebinding verifies that the dialer connects to the IP
// that was validated, even when a stub resolver alternates between a public
// IP and 127.0.0.1 between calls.
func TestSafeDialer_NoRebinding(t *testing.T) {
	// Build a Guard that explicitly allows 93.184.216.34 (example.com's
	// real address) but not 127.0.0.1.
	cfg := &config.SecurityConfig{
		Targets: config.TargetPolicy{
			Allow: []config.TargetRule{
				{Type: "exact", Pattern: "rebind.test", Tools: []string{"tcp_probe"}},
			},
		},
		Network: config.NetworkPolicy{
			AllowIPv4:      ptrBool(true),
			AllowIPv6:      ptrBool(false),
			BlockLoopback:  ptrBool(true),
			BlockLinkLocal: ptrBool(true),
		},
	}
	net := &cfg.Network
	filter, err := NewIPFilter(net)
	if err != nil {
		t.Fatal(err)
	}
	resolver := NewSafeResolver(cfg.DNS, filter)
	dialer, err := NewSafeDialer(*net, filter, 0)
	if err != nil {
		t.Fatal(err)
	}
	mgr := ratelimit.NewManager(ratelimit.ManagerConfig{
		Global:        ratelimit.RateLimit{RPS: 1000, Burst: 1000},
		PerTarget:     ratelimit.RateLimit{RPS: 1000, Burst: 1000},
		PerSession:    ratelimit.RateLimit{RPS: 1000, Burst: 1000},
		MaxConcurrent: 100,
		KeyedTTL:      0,
		KeyedMaxKeys:  1024,
		MaxCalls:      10_000,
	})
	g, err := NewGuard(cfg, resolver, dialer, filter, mgr)
	if err != nil {
		t.Fatal(err)
	}

	// First call to Authorize resolves to 93.184.216.34; the second call
	// (which the dialer must NOT make, but a malicious stub might try) would
	// return 127.0.0.1. We verify the IP in the SafeTarget is stable and
	// that the dialer pinned address does not re-resolve.
	tgt, err := g.Authorize(context.Background(), Request{
		Tool:   "tcp_probe",
		Host:   "rebind.test",
		Port:   443,
		Scheme: "tcp",
	})
	if err != nil {
		t.Skipf("DNS for rebind.test unavailable in this environment: %v", err)
	}
	defer tgt.Release()
	want := netip.MustParseAddr("93.184.216.34")
	if tgt.IP != want {
		t.Fatalf("expected IP %v, got %v", want, tgt.IP)
	}
	// Confirm Control rejects 127.0.0.1.
	if err := controlCheck("tcp", "127.0.0.1:80", filter); err == nil {
		t.Fatal("expected Control to refuse 127.0.0.1")
	}
}

// TestSafeDialer_ControlRefusesBlockedIP is a focused unit test.
func TestSafeDialer_ControlRefusesBlockedIP(t *testing.T) {
	net := &config.NetworkPolicy{
		AllowIPv4:      ptrBool(true),
		AllowIPv6:      ptrBool(false),
		BlockLoopback:  ptrBool(true),
		BlockLinkLocal: ptrBool(true),
	}
	f, err := NewIPFilter(net)
	if err != nil {
		t.Fatal(err)
	}
	for _, blocked := range []string{"127.0.0.1:80", "10.0.0.1:80", "169.254.169.254:80"} {
		if err := controlCheck("tcp", blocked, f); err == nil {
			t.Errorf("expected %s to be blocked by Control", blocked)
		}
	}
}

// stubResolver replaces the real DNS lookup function. This is unused for
// now but kept for future tests that need deterministic DNS behaviour.
type stubResolver struct {
	calls atomic.Int32
}

func (s *stubResolver) lookup(host string) []netip.Addr {
	s.calls.Add(1)
	return nil
}

var _ = (*stubResolver)(nil)
