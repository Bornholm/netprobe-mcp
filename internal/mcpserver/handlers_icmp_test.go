// Tests for the icmp_probe MCP handler. End-to-end coverage is
// limited by the host environment: most CI runners have no ICMP
// capability, so the realistic test is gated on DetectCapability().

package mcpserver

import (
	"context"
	"testing"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/audit"
	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/bornholm/netprobe-mcp/internal/metrics"
	"github.com/bornholm/netprobe-mcp/internal/probe"
	"github.com/bornholm/netprobe-mcp/internal/probe/icmp"
	"github.com/bornholm/netprobe-mcp/internal/ratelimit"
	"github.com/bornholm/netprobe-mcp/internal/security"
)

func newICMPTestServer(t *testing.T, mode icmp.Mode) *Server {
	return newICMPTestServerWithLimits(t, mode, ratelimit.ManagerConfig{
		Global:        ratelimit.RateLimit{RPS: 1000, Burst: 1000},
		PerTarget:     ratelimit.RateLimit{RPS: 1000, Burst: 1000},
		PerSession:    ratelimit.RateLimit{RPS: 1000, Burst: 1000},
		MaxConcurrent: 64,
		KeyedTTL:      time.Minute,
		KeyedMaxKeys:  64,
		MaxCalls:      1000,
	})
}

// newICMPTestServerWithLimits lets rate-weight tests configure a
// tight per-target burst so a Count > burst refusal is observable.
func newICMPTestServerWithLimits(t *testing.T, mode icmp.Mode, rl ratelimit.ManagerConfig) *Server {
	t.Helper()
	cfg := &config.Config{
		Server: config.ServerConfig{Name: "netprobe-mcp-test", Version: "0.1.0"},
		Security: config.SecurityConfig{
			Targets: config.TargetPolicy{
				Allow: []config.TargetRule{
					{Type: "cidr", Pattern: "127.0.0.0/8", Tools: []string{"icmp_probe"}},
				},
			},
			Network: config.NetworkPolicy{
				BlockLoopback:        ptrBool(false),
				BlockLinkLocal:       ptrBool(true),
				AllowIPv4:            ptrBool(true),
				AllowIPv6:            ptrBool(false),
				DisableDefaultBogons: true,
			},
		},
		Limits: config.LimitsConfig{
			Global:              config.RateLimit{RPS: 1000, Burst: 1000},
			PerTarget:           config.RateLimit{RPS: 1000, Burst: 1000},
			PerSession:          config.RateLimit{RPS: 1000, Burst: 1000},
			MaxConcurrentProbes: 8,
			KeyedLimiterTTL:     time.Minute,
			KeyedLimiterMaxKeys: 64,
			MaxCallsPerSession:  1000,
		},
		Probes: config.ProbesConfig{
			DefaultTimeout: 2 * time.Second,
			MaxTimeout:     30 * time.Second,
		},
	}
	filter, err := security.NewIPFilter(&cfg.Security.Network)
	if err != nil {
		t.Fatal(err)
	}
	resolver := security.NewSafeResolver(cfg.Security.DNS, filter)
	dialer, err := security.NewSafeDialer(cfg.Security.Network, filter, cfg.Probes.DefaultTimeout)
	if err != nil {
		t.Fatal(err)
	}
	mgr := ratelimit.NewManager(rl)
	g, err := security.NewGuard(&cfg.Security, resolver, dialer, filter, mgr)
	if err != nil {
		t.Fatal(err)
	}
	logger, _ := audit.New(audit.Config{Format: "json", Output: "stderr", Level: "error"})
	mreg := metrics.New()

	return &Server{
		guard:      g,
		dialer:     dialer,
		limiter:    mgr,
		audit:      logger,
		metrics:    mreg,
		logger:     discardLogger(),
		icmpProber: &ICMPDep{Prober: icmp.NewProber(mode, cfg.Probes.DefaultTimeout, 0, 0, 0)},
		cfg:        cfg,
	}
}

func TestICMPSummary_HappyPath(t *testing.T) {
	res := &icmp.Result{
		Result: probe.Result{
			Success: true,
			Probe:   "icmp_probe",
			Target:  probe.Target{Hostname: "127.0.0.1", ResolvedIP: "127.0.0.1"},
		},
		Mode:            "unprivileged_udp",
		PacketsSent:     3,
		PacketsReceived: 3,
		PacketLossPct:   0,
		MinRTTMs:        0.123,
		AvgRTTMs:        0.456,
		MaxRTTMs:        0.789,
	}
	got := formatICMPSummary(res)
	for _, want := range []string{"icmp_probe OK", "127.0.0.1", "sent=3", "recv=3", "loss=0.00%", "min=0.12", "avg=0.45", "max=0.78", "mode=unprivileged_udp"} {
		if !contains(got, want) {
			t.Errorf("summary missing %q: %s", want, got)
		}
	}
}

func TestICMPSummary_FailurePath(t *testing.T) {
	res := &icmp.Result{
		Result: probe.Result{
			Success: false,
			Probe:   "icmp_probe",
			Target:  probe.Target{Hostname: "127.0.0.1"},
		},
		PacketsSent:     3,
		PacketsReceived: 0,
		PacketLossPct:   100,
	}
	got := formatICMPSummary(res)
	if !contains(got, "icmp_probe FAILED") {
		t.Errorf("expected FAILED: %s", got)
	}
	if !contains(got, "0 replies of 3 sent") {
		t.Errorf("expected '0 replies of 3 sent': %s", got)
	}
}

// TestHandleICMPProbe_ValidationRejection exercises the
// "validate before authorise" half of the pipeline: a malformed
// payload must surface as a refusal without the Guard being
// consulted.
func TestHandleICMPProbe_ValidationRejection(t *testing.T) {
	s := newICMPTestServer(t, icmp.ModeUnprivileged)

	_, _, err := s.handleICMPProbe(context.Background(), nil, icmp.Options{})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

// TestHandleICMPProbe_RateWeightRefusal verifies that an icmp_probe
// call with Count > per_target.burst is refused by the rate limiter
// (PLAN §7.4: "count packets => count tokens"). The pipeline must
// short-circuit before any ICMP packet is sent.
func TestHandleICMPProbe_RateWeightRefusal(t *testing.T) {
	s := newICMPTestServerWithLimits(t, icmp.ModeUnprivileged, ratelimit.ManagerConfig{
		Global:        ratelimit.RateLimit{RPS: 1000, Burst: 1000},
		PerTarget:     ratelimit.RateLimit{RPS: 1000, Burst: 2}, // tight burst
		PerSession:    ratelimit.RateLimit{RPS: 1000, Burst: 1000},
		MaxConcurrent: 8,
		KeyedTTL:      time.Minute,
		KeyedMaxKeys:  64,
		MaxCalls:      1000,
	})
	_, _, err := s.handleICMPProbe(context.Background(), nil, icmp.Options{
		Host:       "127.0.0.1",
		Count:      5, // exceeds per-target burst of 2
		IntervalMs: 200,
	})
	if err == nil {
		t.Fatal("expected rate-limit refusal for Count=5 with burst=2")
	}
}

func TestFmtIntAndFloat(t *testing.T) {
	if got := fmtInt(0); got != "0" {
		t.Errorf("fmtInt(0) = %q", got)
	}
	if got := fmtInt(42); got != "42" {
		t.Errorf("fmtInt(42) = %q", got)
	}
	if got := fmtInt(-7); got != "-7" {
		t.Errorf("fmtInt(-7) = %q", got)
	}
	if got := fmtFloat(0); got != "0.00" {
		t.Errorf("fmtFloat(0) = %q", got)
	}
	if got := fmtFloat(1.5); got != "1.50" {
		t.Errorf("fmtFloat(1.5) = %q", got)
	}
	if got := fmtFloat(2.789); got != "2.78" {
		t.Errorf("fmtFloat(2.789) = %q", got)
	}
}
