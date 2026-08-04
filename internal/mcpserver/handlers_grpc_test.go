// Tests for the grpc_probe MCP handler. End-to-end coverage via
// in-memory MCP transports so we exercise the full pipeline
// (validate → authorise → execute → audit → summarise) without
// depending on a network.
//
// The gRPC backend is a tiny in-process h2c server that speaks the
// Health Checking Protocol well enough to satisfy the prober. See
// ../probe/grpc_test.go for unit tests of the prober itself.

package mcpserver

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/audit"
	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/bornholm/netprobe-mcp/internal/metrics"
	"github.com/bornholm/netprobe-mcp/internal/probe"
	"github.com/bornholm/netprobe-mcp/internal/ratelimit"
	"github.com/bornholm/netprobe-mcp/internal/security"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// startGRPCTestServer boots an h2c server on 127.0.0.1 that
// implements /grpc.health.v1.Health/Check. healthyNames is the set
// of services that return SERVING; others return SERVICE_UNKNOWN.
// Returns the listener, the bound host:port, and a call counter.
func startGRPCTestServer(t *testing.T, healthyNames map[string]bool) (net.Listener, string, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/grpc.health.v1.Health/Check", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		service := sniffGRPCService(r)
		status := "0"
		msg := ""
		if service != "" && !healthyNames[service] {
			status = "5"
			msg = "service not found: " + service
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		w.Header().Set("Grpc-Status", status)
		if msg != "" {
			w.Header().Set("Grpc-Message", msg)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00})
		_, _ = io.Copy(io.Discard, r.Body)
	})

	srv := &http.Server{Handler: h2c.NewHandler(mux, &http2.Server{})}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return ln, ln.Addr().String(), &calls
}

// sniffGRPCService decodes the gRPC HealthCheckRequest body to
// extract the optional service field. Duplicated from the
// internal/probe test helper to keep packages hermetic.
func sniffGRPCService(r *http.Request) string {
	buf := make([]byte, 256)
	n, _ := r.Body.Read(buf)
	if n < 5 {
		return ""
	}
	msgLen := uint32(buf[1])<<24 | uint32(buf[2])<<16 | uint32(buf[3])<<8 | uint32(buf[4])
	if msgLen == 0 || n < int(5+msgLen) {
		return ""
	}
	body := buf[5 : 5+msgLen]
	if len(body) < 2 || body[0] != 0x0a {
		return ""
	}
	vl := int(body[1])
	if 2+vl > len(body) {
		return ""
	}
	return string(body[2 : 2+vl])
}

// newGRPCTestServer builds a Server with a GRPCProber wired in.
// The allow-list covers 127.0.0.0/8.
func newGRPCTestServer(t *testing.T, defaultPort uint16) *Server {
	t.Helper()
	cfg := &config.Config{
		Server: config.ServerConfig{Name: "netprobe-mcp-test", Version: "0.1.0"},
		Security: config.SecurityConfig{
			Targets: config.TargetPolicy{
				Allow: []config.TargetRule{
					{Type: "cidr", Pattern: "127.0.0.0/8", Tools: []string{"grpc_probe"}},
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
			GRPC:           config.GRPCProbeConfig{Enabled: true, DefaultPort: defaultPort},
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
		Global:        ratelimit.RateLimit{RPS: 1000, Burst: 1000},
		PerTarget:     ratelimit.RateLimit{RPS: 1000, Burst: 1000},
		PerSession:    ratelimit.RateLimit{RPS: 1000, Burst: 1000},
		MaxConcurrent: 8,
		KeyedTTL:      time.Minute,
		KeyedMaxKeys:  64,
		MaxCalls:      1000,
	})
	guard, err := security.NewGuard(&cfg.Security, resolver, dialer, filter, mgr)
	if err != nil {
		t.Fatal(err)
	}
	logger, _ := audit.New(audit.Config{Format: "json", Output: "stderr", Level: "error"})
	mreg := metrics.New()

	return &Server{
		guard:   guard,
		dialer:  dialer,
		limiter: mgr,
		audit:   logger,
		metrics: mreg,
		logger:  discardLogger(),
		grpcProber: &GRPCDep{
			Prober:           probe.NewGRPCProber(cfg.Probes.DefaultTimeout, cfg.Probes.GRPC.DefaultPort),
			DialTimeout:      cfg.Probes.DefaultTimeout,
			DefaultPort:      cfg.Probes.GRPC.DefaultPort,
			HandshakeTimeout: cfg.Probes.GRPC.HandshakeTimeout,
		},
		cfg: cfg,
	}
}

// TestHandleGRPCProbe_HappyPath drives the full MCP handler against
// an in-process h2c server that returns SERVING.
func TestHandleGRPCProbe_HappyPath(t *testing.T) {
	_, addr, calls := startGRPCTestServer(t, map[string]bool{"": true})
	s := newGRPCTestServer(t, 0)

	port := uint16(extractPort(t, addr))
	res, _, err := s.handleGRPCProbe(context.Background(), nil, probe.GRPCOptions{
		Host: "127.0.0.1",
		Port: int(port),
	})
	if err != nil {
		t.Fatalf("handleGRPCProbe: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected IsError=false, got true: %+v", res)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("server got %d calls, want 1", got)
	}
	if len(res.Content) == 0 {
		t.Fatal("expected a text summary")
	}
	txt, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("unexpected content type %T", res.Content[0])
	}
	if !contains(txt.Text, "SERVING") {
		t.Errorf("summary missing SERVING: %s", txt.Text)
	}
}

// TestHandleGRPCProbe_ServiceUnknown ensures the handler surfaces
// SERVICE_UNKNOWN as a non-tool error (Success=false in the
// structured payload).
func TestHandleGRPCProbe_ServiceUnknown(t *testing.T) {
	healthy := map[string]bool{"my.svc": true}
	_, addr, _ := startGRPCTestServer(t, healthy)
	s := newGRPCTestServer(t, 0)

	port := uint16(extractPort(t, addr))
	_, out, err := s.handleGRPCProbe(context.Background(), nil, probe.GRPCOptions{
		Host:    "127.0.0.1",
		Port:    int(port),
		Service: "does.not.exist",
	})
	if err != nil {
		t.Fatalf("handleGRPCProbe: %v", err)
	}
	if out.Success {
		t.Fatalf("expected Success=false for unknown service, got %+v", out.GRPC)
	}
	if out.GRPC == nil || out.GRPC.HealthStatus != "SERVICE_UNKNOWN" {
		t.Errorf("HealthStatus = %v, want SERVICE_UNKNOWN", out.GRPC)
	}
}

// TestHandleGRPCProbe_DeniedByPolicy ensures an off-allowlist host
// is refused with IsError=true (policy denial, not network failure).
// MarkDenied is the audit-event marker; the framework strips it
// from the surfaced error after the audit middleware logs the
// event, so we accept either a non-nil err OR IsError=true on the
// returned CallToolResult.
func TestHandleGRPCProbe_DeniedByPolicy(t *testing.T) {
	s := newGRPCTestServer(t, 0)
	res, _, _ := s.handleGRPCProbe(context.Background(), nil, probe.GRPCOptions{
		Host: "10.255.255.1", // not in 127.0.0.0/8
		Port: 50051,
	})
	if !res.IsError {
		t.Fatalf("expected IsError=true for refused target")
	}
	if len(res.Content) == 0 {
		t.Fatalf("expected a refusal message")
	}
}

// TestHandleGRPCProbe_RejectsNegativePort ensures input validation
// runs before the rate-limit budget is burned.
func TestHandleGRPCProbe_RejectsNegativePort(t *testing.T) {
	s := newGRPCTestServer(t, 0)
	res, _, _ := s.handleGRPCProbe(context.Background(), nil, probe.GRPCOptions{
		Host: "127.0.0.1",
		Port: -1,
	})
	if !res.IsError {
		t.Errorf("expected IsError=true for negative port")
	}
}

// TestProbePolicy_ReportsGRPCProbe verifies that probe_policy
// mentions grpc_probe when the GRPCProber dep is wired.
func TestProbePolicy_ReportsGRPCProbe(t *testing.T) {
	s := newGRPCTestServer(t, 50051)
	_, out, err := s.handleProbePolicy(context.Background(), nil, struct{}{})
	if err != nil {
		t.Fatalf("handleProbePolicy: %v", err)
	}
	found := false
	for _, p := range out.Probes {
		if p == "grpc_probe" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("grpc_probe missing from probe_policy output: %v", out.Probes)
	}
}

// TestIntegration_GRPCProbe_HappyPath drives the full MCP
// pipeline through in-memory transports. This is the closest the
// test suite gets to a real agent scenario without spinning up an
// LLM client.
func TestIntegration_GRPCProbe_HappyPath(t *testing.T) {
	_, addr, calls := startGRPCTestServer(t, map[string]bool{"": true})
	s := buildGRPCTestServer(t)

	ct, st := mcp.NewInMemoryTransports()
	ss, err := s.MCP().Connect(context.Background(), st, nil)
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

	port := extractPort(t, addr)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "grpc_probe",
		Arguments: map[string]any{
			"host": "127.0.0.1",
			"port": int(port),
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected IsError=false, got %+v", res)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("server got %d calls, want 1", got)
	}

	var out probe.GRPCProbeResult
	scBytes, mErr := json.Marshal(res.StructuredContent)
	if mErr != nil {
		t.Fatalf("marshal: %v", mErr)
	}
	if err := json.Unmarshal(scBytes, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.Success {
		t.Errorf("expected Success=true, got %+v", out)
	}
	if out.GRPC == nil || out.GRPC.HealthStatus != "SERVING" {
		t.Errorf("HealthStatus = %v, want SERVING", out.GRPC)
	}
}

// buildGRPCTestServer wires a Server through mcpserver.New so the
// MCP framework is properly initialised (in particular s.MCP() is
// non-nil). Mirrors newGRPCTestServer but uses the public
// constructor.
func buildGRPCTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{
		Server: config.ServerConfig{Name: "netprobe-mcp-test", Version: "0.1.0"},
		Security: config.SecurityConfig{
			Targets: config.TargetPolicy{
				Allow: []config.TargetRule{
					{Type: "cidr", Pattern: "127.0.0.0/8", Tools: []string{"grpc_probe"}},
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
			GRPC:           config.GRPCProbeConfig{Enabled: true, DefaultPort: 50051},
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
		Global:        ratelimit.RateLimit{RPS: 1000, Burst: 1000},
		PerTarget:     ratelimit.RateLimit{RPS: 1000, Burst: 1000},
		PerSession:    ratelimit.RateLimit{RPS: 1000, Burst: 1000},
		MaxConcurrent: 8,
		KeyedTTL:      time.Minute,
		KeyedMaxKeys:  64,
		MaxCalls:      1000,
	})
	guard, err := security.NewGuard(&cfg.Security, resolver, dialer, filter, mgr)
	if err != nil {
		t.Fatal(err)
	}
	logger, _ := audit.New(audit.Config{Format: "json", Output: "stderr", Level: "error"})
	mreg := metrics.New()

	return New(&mcp.Implementation{Name: cfg.Server.Name, Version: cfg.Server.Version}, Deps{
		Guard:   guard,
		Limiter: mgr,
		Audit:   logger,
		Metrics: mreg,
		Logger:  discardLogger(),
		GRPCProber: &GRPCDep{
			Prober:           probe.NewGRPCProber(cfg.Probes.DefaultTimeout, cfg.Probes.GRPC.DefaultPort),
			DialTimeout:      cfg.Probes.DefaultTimeout,
			DefaultPort:      cfg.Probes.GRPC.DefaultPort,
			HandshakeTimeout: cfg.Probes.GRPC.HandshakeTimeout,
		},
		Instructions: "test",
		Config:       cfg,
	})
}

// extractPort splits a host:port string and returns the port
// integer. test helper kept here so the gRPC tests are hermetic.
func extractPort(t *testing.T, addr string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	var p int
	if _, err := json.Marshal(0); err != nil {
		t.Fatal(err)
	}
	for _, c := range portStr {
		if c < '0' || c > '9' {
			t.Fatalf("non-digit in port %q", portStr)
		}
		p = p*10 + int(c-'0')
	}
	return p
}
