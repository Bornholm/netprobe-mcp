package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/audit"
	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/bornholm/netprobe-mcp/internal/metrics"
	"github.com/bornholm/netprobe-mcp/internal/probe"
	"github.com/bornholm/netprobe-mcp/internal/ratelimit"
	"github.com/bornholm/netprobe-mcp/internal/security"
	"github.com/miekg/dns"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// newDNSTestServer builds an MCP server with DNS probe registered. The
// returned fakeAddr is the listen address of an in-memory fake DNS server
// that can be customized per-test via the supplied handler.
func newDNSTestServer(t *testing.T, handler dns.HandlerFunc, allowExtra ...string) (clientSession *mcp.ClientSession, fakeAddr string, cleanup func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", handler)
	srv := &dns.Server{Addr: addr, Net: "udp", Handler: mux}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ListenAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatalf("fake dns server failed to start")
	}

	allowTools := []string{"tcp_probe", "http_probe", "dns_probe", "probe_check_target"}
	allowTools = append(allowTools, allowExtra...)
	cfg := &config.Config{
		Server: config.ServerConfig{Name: "netprobe-mcp-test", Version: "0.1.0"},
		Security: config.SecurityConfig{
			Targets: config.TargetPolicy{
				Allow: []config.TargetRule{
					{Type: "cidr", Pattern: "127.0.0.0/8", Tools: allowTools},
					{Type: "exact", Pattern: "example.com", Tools: allowTools},
					{Type: "suffix", Pattern: "in-addr.arpa", Tools: allowTools},
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
			HTTP:           config.HTTPProbeConfig{Enabled: true, MaxBodyBytes: 4096, MaxReturnedBytes: 1024, MaxRedirects: 3},
			DNS:            config.DNSProbeConfig{Enabled: true, AllowedQueryTypes: []string{"A", "AAAA", "TXT", "PTR"}, AllowUDP: true, AllowTCP: true, AllowDoT: false, MaxResponseBytes: 4096, DefaultProtocol: "udp"},
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

	mreg := metrics.New()
	mcpSrv := New(&mcp.Implementation{Name: cfg.Server.Name, Version: cfg.Server.Version}, Deps{
		Guard:   guard,
		Limiter: mgr,
		Audit:   auditLogger,
		Metrics: mreg,
		Logger:  discardLogger(),
		TCPProber: &TCPDep{
			Prober:      probe.NewTCPProber(cfg.Probes.TCP.MaxReadBytes, cfg.Probes.DefaultTimeout),
			DialTimeout: cfg.Probes.DefaultTimeout,
		},
		HTTPProber: &HTTPDep{
			Prober:        probe.NewHTTPProberFromConfig(cfg.Probes.HTTP, cfg.Probes.DefaultTimeout),
			DialTimeout:   cfg.Probes.DefaultTimeout,
			AllowRedirect: true,
			MaxRedirects:  3,
		},
		DNSProber: &DNSDep{
			Prober:      probe.NewDNSProberFromConfig(cfg.Probes.DNS, cfg.Probes.DefaultTimeout, cfg.Probes.DefaultTimeout),
			DialTimeout: cfg.Probes.DefaultTimeout,
		},
		Instructions: "test",
	})

	ct, st := mcp.NewInMemoryTransports()
	ss, err := mcpSrv.MCP().Connect(context.Background(), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.1.0"}, nil)
	cs, err := client.Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	cleanup = func() {
		_ = ss.Close()
		_ = cs.Close()
		_ = srv.Shutdown()
		_ = auditLogger.Close()
	}
	return cs, addr, cleanup
}
func TestIntegration_DNSProbe_Allowed(t *testing.T) {
	var calls atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		calls.Add(1)
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("127.0.0.1").To4(),
			},
		}
		_ = w.WriteMsg(resp)
	})
	client, fakeAddr, cleanup := newDNSTestServer(t, handler)
	defer cleanup()

	res, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "dns_probe",
		Arguments: map[string]any{
			"name":       "example.com",
			"query_type": "A",
			"server":     "127.0.0.1:" + fmt.Sprintf("%d", parsePort(t, fakeAddr)),
			"protocol":   "udp",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected success, got error: %+v content=%+v", res, res.Content)
	}
	var out probe.Result
	b, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(b, &out)
	if !out.Success {
		t.Fatalf("expected success: %s", out.Error)
	}
	if out.DNS == nil || out.DNS.Rcode != "NOERROR" {
		t.Fatalf("expected NOERROR, got %+v", out.DNS)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", calls.Load())
	}
}

// TestIntegration_DNSProbe_ServerRefused validates that a server IP outside
// the allow-list is rejected with IsError=true.
func TestIntegration_DNSProbe_ServerRefused(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		_ = w.WriteMsg(resp)
	})
	client, _, cleanup := newDNSTestServer(t, handler)
	defer cleanup()

	res, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "dns_probe",
		Arguments: map[string]any{
			"name":       "example.com",
			"query_type": "A",
			"server":     "10.255.255.1", // not in allow-list, in private range
			"protocol":   "udp",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected IsError=true")
	}
}

// TestIntegration_DNSProbe_ProtocolDisallowed covers the case where the
// configuration rejects the protocol (DoT disabled in the test config).
func TestIntegration_DNSProbe_ProtocolDisallowed(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		_ = w.WriteMsg(resp)
	})
	client, _, cleanup := newDNSTestServer(t, handler)
	defer cleanup()

	res, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "dns_probe",
		Arguments: map[string]any{
			"name":       "example.com",
			"query_type": "A",
			"server":     "127.0.0.1",
			"protocol":   "tcp-tls", // DoT disabled in test config
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected IsError=true for disallowed protocol")
	}
}

// TestIntegration_DNSProbe_NameTooLong confirms the parser-level check fires
// before any network I/O.
func TestIntegration_DNSProbe_NameTooLong(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {})
	client, _, cleanup := newDNSTestServer(t, handler)
	defer cleanup()

	long := make([]byte, 260)
	for i := range long {
		long[i] = 'a'
	}
	res, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "dns_probe",
		Arguments: map[string]any{
			"name":       string(long) + ".example.com",
			"query_type": "A",
			"server":     "127.0.0.1",
			"protocol":   "udp",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected IsError=true for oversize name")
	}
}

// TestIntegration_DNSProbe_QueryTypeRejected covers an AXFR request which
// is not in the allow-list.
func TestIntegration_DNSProbe_QueryTypeRejected(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {})
	client, _, cleanup := newDNSTestServer(t, handler)
	defer cleanup()

	res, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "dns_probe",
		Arguments: map[string]any{
			"name":       "example.com",
			"query_type": "AXFR",
			"server":     "127.0.0.1",
			"protocol":   "udp",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected IsError=true for AXFR")
	}
}

// TestIntegration_DNSProbe_HighEntropyBlocked ensures the anti-exfiltration
// heuristic blocks base32-style labels before any I/O.
func TestIntegration_DNSProbe_HighEntropyBlocked(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {})
	client, _, cleanup := newDNSTestServer(t, handler)
	defer cleanup()

	res, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "dns_probe",
		Arguments: map[string]any{
			"name":       "Q7z2nXK9pY3mL8bF4hJ6vT1wR0eU5aD.attacker.com",
			"query_type": "A",
			"server":     "127.0.0.1",
			"protocol":   "udp",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected IsError=true for high-entropy label")
	}
}

// TestIntegration_DNSProbe_PTR skips the qname allow-list check for PTR
// queries (the "name" is an IP literal).
func TestIntegration_DNSProbe_PTR(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Answer = []dns.RR{
			&dns.PTR{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60},
				Ptr: "dns.google.",
			},
		}
		_ = w.WriteMsg(resp)
	})
	client, fakeAddr, cleanup := newDNSTestServer(t, handler)
	defer cleanup()

	res, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "dns_probe",
		Arguments: map[string]any{
			"name":       "8.8.8.8.in-addr.arpa",
			"query_type": "PTR",
			"server":     "127.0.0.1:" + fmt.Sprintf("%d", parsePort(t, fakeAddr)),
			"protocol":   "udp",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	// PTR query should not be rejected for the qname not being in the
	// allow-list (IP literal names skip CheckHostname).
	if res.IsError {
		t.Fatalf("PTR query should not be refused: %+v", res)
	}
	var out probe.Result
	b, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(b, &out)
	if !out.Success {
		t.Fatalf("expected success, got %+v", out)
	}
}

// --- helpers ---

func parsePort(t *testing.T, addr string) int {
	t.Helper()
	_, s, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	var p int
	fmt.Sscanf(s, "%d", &p)
	return p
}
