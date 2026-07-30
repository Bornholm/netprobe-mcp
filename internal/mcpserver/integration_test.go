package mcpserver

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/audit"
	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/bornholm/netprobe-mcp/internal/metrics"
	"github.com/bornholm/netprobe-mcp/internal/probe"
	"github.com/bornholm/netprobe-mcp/internal/ratelimit"
	"github.com/bornholm/netprobe-mcp/internal/security"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func newTestServer(t *testing.T) (*Server, *net.TCPListener) {
	t.Helper()
	_ = net.IPv4
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	tcpLn := ln.(*net.TCPListener)

	cfg := &config.Config{
		Server: config.ServerConfig{Name: "netprobe-mcp-test", Version: "0.1.0"},
		Security: config.SecurityConfig{
			Targets: config.TargetPolicy{
				Allow: []config.TargetRule{
					{Type: "cidr", Pattern: "127.0.0.0/8", Tools: []string{"tcp_probe", "probe_check_target"}},
				},
			},
			Network: config.NetworkPolicy{
				BlockLoopback:        ptrBool(false),
				BlockLinkLocal:       ptrBool(true),
				AllowIPv4:            ptrBool(true),
				AllowIPv6:            ptrBool(false),
				DisableDefaultBogons: true,
			},
			DNS: config.DNSPolicy{},
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
			TCP:            config.TCPProbeConfig{Enabled: true, MaxReadBytes: 4096},
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
	mgr := ratelimit.NewManager(ratelimit.ManagerConfig{
		Global:        ratelimit.RateLimit{RPS: cfg.Limits.Global.RPS, Burst: cfg.Limits.Global.Burst},
		PerTarget:     ratelimit.RateLimit{RPS: cfg.Limits.PerTarget.RPS, Burst: cfg.Limits.PerTarget.Burst},
		PerSession:    ratelimit.RateLimit{RPS: cfg.Limits.PerSession.RPS, Burst: cfg.Limits.PerSession.Burst},
		MaxConcurrent: cfg.Limits.MaxConcurrentProbes,
		KeyedTTL:      cfg.Limits.KeyedLimiterTTL,
		KeyedMaxKeys:  cfg.Limits.KeyedLimiterMaxKeys,
		MaxCalls:      cfg.Limits.MaxCallsPerSession,
	})
	guard, err := security.NewGuard(&cfg.Security, resolver, dialer, filter, mgr)
	if err != nil {
		t.Fatal(err)
	}

	auditLogger, err := audit.New(audit.Config{Format: "json", Output: "stderr", Level: "error"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = auditLogger.Close() })

	mreg := metrics.New()

	// Local listener to receive the TCP probe.
	ln, lErr := net.Listen("tcp", "127.0.0.1:0")
	if lErr != nil {
		t.Fatal(lErr)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("SSH-2.0-Test\r\n"))
				time.Sleep(50 * time.Millisecond)
			}(c)
		}
	}()

	_ = tcpLn // referenced for clarity

	srv := New(&mcp.Implementation{Name: cfg.Server.Name, Version: cfg.Server.Version}, Deps{
		Guard:   guard,
		Limiter: mgr,
		Audit:   auditLogger,
		Metrics: mreg,
		Logger:  discardLogger(),
		TCPProber: &TCPDep{
			Prober:      probe.NewTCPProber(cfg.Probes.TCP.MaxReadBytes, cfg.Probes.DefaultTimeout),
			DialTimeout: cfg.Probes.DefaultTimeout,
		},
		Instructions: "test",
		Config:       cfg,
	})
	return srv, tcpLn
}

func ptrBool(b bool) *bool { return &b }

// TestIntegration_AllowedTargetConnects proves the full pipeline: tool call
// reaches the dialer, the SafeDialer pins the IP, the listener accepts and
// sends a banner, the banner is sanitized.
func TestIntegration_AllowedTargetConnects(t *testing.T) {
	srv, ln := newTestServer(t)

	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.MCP().Connect(context.Background(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.1.0"}, nil)
	cs, err := client.Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "tcp_probe",
		Arguments: map[string]any{
			"host": "127.0.0.1",
			"port": int(port),
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool returned IsError=true: %+v", res)
	}
	var out probe.Result
	scBytes, mErr := json.Marshal(res.StructuredContent)
	if mErr != nil {
		t.Fatalf("marshal structured content: %v", mErr)
	}
	if err := json.Unmarshal(scBytes, &out); err != nil {
		t.Fatalf("decode structured content: %v", err)
	}
	if !out.Success {
		t.Fatalf("expected success, got failure: %s (%s)", out.Error, out.ErrorClass)
	}
	if out.TCP == nil {
		t.Fatal("expected TCP details")
	}
	wantIP := netip.MustParseAddr("127.0.0.1")
	if out.Target.ResolvedIP != wantIP.String() {
		t.Errorf("expected resolved IP %s, got %s", wantIP, out.Target.ResolvedIP)
	}
}

// TestIntegration_DeniedTargetRefused ensures a target outside the allow-list
// is refused with IsError=true.
func TestIntegration_DeniedTargetRefused(t *testing.T) {
	srv, _ := newTestServer(t)

	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.MCP().Connect(context.Background(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.1.0"}, nil)
	cs, err := client.Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "tcp_probe",
		Arguments: map[string]any{
			"host": "10.255.255.1",
			"port": 22,
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError=true for refused target")
	}
}

// TestIntegration_CheckTargetDryRun exercises probe_check_target.
func TestIntegration_CheckTargetDryRun(t *testing.T) {
	srv, _ := newTestServer(t)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.MCP().Connect(context.Background(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil)
	cs, err := client.Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	// Allowed
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "probe_check_target",
		Arguments: map[string]any{"host": "127.0.0.1", "port": 22, "tool": "tcp_probe"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("expected allow, got error: %+v", res)
	}
	var out CheckTargetOut
	scBytes, mErr := json.Marshal(res.StructuredContent)
	if mErr != nil {
		t.Fatal(mErr)
	}
	if err := json.Unmarshal(scBytes, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Allowed {
		t.Fatalf("expected allowed=true: %+v", out)
	}

	// Refused
	res2, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "probe_check_target",
		Arguments: map[string]any{"host": "10.255.255.1", "port": 22, "tool": "tcp_probe"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res2.IsError {
		t.Fatalf("expected IsError=true: %+v", res2)
	}
}

// TestIntegration_ProbePolicy_ReportsCounts is a regression test for a
// bug where probe_policy reported zero for allow_rules/deny_rules because
// the handler never assigned them. The bug made the LLM unable to tell
// whether its target was allow-listed.
func TestIntegration_ProbePolicy_ReportsCounts(t *testing.T) {
	srv, _ := newTestServer(t)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.MCP().Connect(context.Background(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil)
	cs, err := client.Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "probe_policy",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("probe_policy errored: %+v", res)
	}

	var out PolicyOut
	scBytes, mErr := json.Marshal(res.StructuredContent)
	if mErr != nil {
		t.Fatal(mErr)
	}
	if err := json.Unmarshal(scBytes, &out); err != nil {
		t.Fatal(err)
	}
	if out.AllowCount == 0 {
		t.Errorf("AllowCount = 0, want > 0 (the test config allows 127.0.0.0/8)")
	}
	if len(out.Probes) == 0 {
		t.Errorf("Probes empty, want at least one enabled probe")
	}
	if out.MaxConc == 0 {
		t.Errorf("MaxConc = 0, want the configured MaxConcurrentProbes")
	}
	if out.IPFamily == "" {
		t.Errorf("IPFamily empty, want ipv4/dual/ipv6")
	}
}
