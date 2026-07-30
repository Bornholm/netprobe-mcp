package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
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

// newAuditServer is a copy of newTestServer that captures audit output into
// a buffer instead of writing to stderr. The buffer is drained synchronously
// for denied events.
// auditWithBuf wraps a buffer with a mutex for race-safe access from both
// the writer (slog handler) and the test goroutine.
type auditWithBuf struct {
	mu sync.Mutex
	b  *bytes.Buffer
}

func (a *auditWithBuf) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.b.Write(p)
}

func (a *auditWithBuf) String() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.b.String()
}

func newAuditServer(t *testing.T) (*Server, *auditWithBuf) {
	t.Helper()
	aw := &auditWithBuf{b: &bytes.Buffer{}}

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

	auditLogger, err := audit.New(audit.Config{Format: "json", Level: "info", Writer: aw})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = auditLogger.Close() })

	mreg := metrics.New()

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
	})
	return srv, aw
}

// lockedWriter is kept for backward compatibility with older callers.
type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func TestAudit_EmitsDeniedForRefusedCall(t *testing.T) {
	srv, aw := newAuditServer(t)

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
		Name:      "probe_check_target",
		Arguments: map[string]any{"host": "10.255.255.1", "port": 22, "tool": "tcp_probe"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError=true")
	}

	// Refusals are written synchronously.
	raw := aw.String()
	if !strings.Contains(raw, `"decision":"denied"`) {
		t.Fatalf("expected denied decision in audit log, got: %s", raw)
	}
	if !strings.Contains(raw, `"outcome":"policy_denied"`) {
		t.Fatalf("expected policy_denied outcome, got: %s", raw)
	}

	dec := json.NewDecoder(strings.NewReader(raw))
	var ev map[string]any
	if err := dec.Decode(&ev); err != nil {
		t.Fatalf("decode audit event: %v\nraw=%s", err, raw)
	}
	if ev["tool"] != "probe_check_target" {
		t.Errorf("tool = %v, want probe_check_target", ev["tool"])
	}
	if ev["deny_reason"] == nil || ev["deny_reason"] == "" {
		t.Errorf("deny_reason missing")
	}
}

func TestAudit_EmitsSuccessForAllowedProbe(t *testing.T) {
	srv, aw := newAuditServer(t)

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
		Name:      "probe_check_target",
		Arguments: map[string]any{"host": "127.0.0.1", "port": 80, "tool": "tcp_probe"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("expected allow, got error: %+v", res)
	}

	// Allowed events go through the async channel; poll briefly.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(aw.String(), `"outcome":"success"`) {
		time.Sleep(10 * time.Millisecond)
	}
	raw := aw.String()
	if !strings.Contains(raw, `"outcome":"success"`) {
		t.Fatalf("expected success outcome, got: %s", raw)
	}
}
