package mcpserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/audit"
	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/bornholm/netprobe-mcp/internal/metrics"
	"github.com/bornholm/netprobe-mcp/internal/probe"
	"github.com/bornholm/netprobe-mcp/internal/probe/tlsdiag"
	"github.com/bornholm/netprobe-mcp/internal/ratelimit"
	"github.com/bornholm/netprobe-mcp/internal/security"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// newTLSTestServer builds an MCP server with tls_diagnose registered
// plus an in-memory TLS server. The returned fakeAddr is the listen
// address of the in-memory TLS server.
func newTLSTestServer(t *testing.T) (clientSession *mcp.ClientSession, fakeAddr string, fakeRoot *x509.Certificate, cleanup func()) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	now := time.Now()
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(2 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tc, ok := c.(*tls.Conn)
				if !ok {
					return
				}
				_ = tc.Handshake()
				<-done
			}(conn)
		}
	}()

	pool := x509.NewCertPool()
	pool.AddCert(rootCert)

	allowTools := []string{"tcp_probe", "http_probe", "dns_probe", "tls_diagnose", "probe_check_target"}
	cfg := &config.Config{
		Server: config.ServerConfig{Name: "netprobe-mcp-test", Version: "0.1.0"},
		Security: config.SecurityConfig{
			Targets: config.TargetPolicy{
				Allow: []config.TargetRule{
					{Type: "cidr", Pattern: "127.0.0.0/8", Tools: allowTools},
					{Type: "exact", Pattern: "localhost.example.com", Tools: allowTools},
					{Type: "exact", Pattern: "wrong.example.org", Tools: allowTools},
					{Type: "suffix", Pattern: "evil.example.org", Tools: allowTools},
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
			DNS:            config.DNSProbeConfig{Enabled: true, AllowedQueryTypes: []string{"A"}, AllowUDP: true, AllowTCP: true, AllowDoT: false, MaxResponseBytes: 4096, DefaultProtocol: "udp"},
			TLS: config.TLSDiagConfig{
				Enabled:               true,
				DefaultPort:           parsePortFromAddr(t, ln.Addr().String()),
				TotalBudget:           5 * time.Second,
				HandshakeTimeout:      2 * time.Second,
				MinTLSVersion:         "1.2",
				MaxTLSVersion:         "1.3",
				ExpiringSoonDays:      30,
				ExpiringCriticalDays:  7,
				MaxValidityDays:       398,
				ExcessiveValidityDays: 825,
				MinRSAKeyBits:         2048,
				MinECKeyBits:          256,
			},
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
		PerTarget:     ratelimit.RateLimit{RPS: cfg.Limits.PerTarget.RPS, Burst: int(cfg.Limits.PerTarget.Burst)},
		PerSession:    ratelimit.RateLimit{RPS: cfg.Limits.PerSession.RPS, Burst: int(cfg.Limits.PerSession.Burst)},
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
	tlsAn := tlsdiag.NewAnalyzer(tlsdiag.Config{
		Enabled:               true,
		TotalBudget:           cfg.Probes.TLS.TotalBudget,
		HandshakeTimeout:      cfg.Probes.TLS.HandshakeTimeout,
		MinTLSVersion:         tls.VersionTLS12,
		MaxTLSVersion:         tls.VersionTLS13,
		ExpiringSoonDays:      cfg.Probes.TLS.ExpiringSoonDays,
		ExpiringCriticalDays:  cfg.Probes.TLS.ExpiringCriticalDays,
		MaxValidityDays:       cfg.Probes.TLS.MaxValidityDays,
		ExcessiveValidityDays: cfg.Probes.TLS.ExcessiveValidityDays,
		MinRSAKeyBits:         cfg.Probes.TLS.MinRSAKeyBits,
		MinECKeyBits:          cfg.Probes.TLS.MinECKeyBits,
		Roots:                 pool,
		Dialer:                dialer,
		Now:                   time.Now,
	})
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
		TLSDiagnoser: &TLSDep{Analyzer: tlsAn},
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
		close(done)
		_ = ln.Close()
		_ = auditLogger.Close()
	}
	return cs, ln.Addr().String(), rootCert, cleanup
}

// --- tests ---

func TestIntegration_TLSDiagnose_Allowed(t *testing.T) {
	client, addr, _, cleanup := newTLSTestServer(t)
	defer cleanup()

	port := parsePortFromAddr(t, addr)
	res, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "tls_diagnose",
		Arguments: map[string]any{
			"host": "127.0.0.1",
			"port": port,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected success, got error: %+v content=%+v", res, res.Content)
	}
	var out tlsdiag.Report
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v (raw=%s)", err, string(b))
	}
	if !out.Handshake.Succeeded {
		t.Errorf("expected handshake success, got failure: %s", out.Handshake.FailureReason)
	}
	if !out.Chain.Complete {
		t.Errorf("expected complete chain, got %+v", out.Chain)
	}
}

func TestIntegration_TLSDiagnose_HostDenied(t *testing.T) {
	client, _, _, cleanup := newTLSTestServer(t)
	defer cleanup()

	res, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "tls_diagnose",
		Arguments: map[string]any{
			"host": "evil.example.org",
			"port": 443,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected IsError=true for non-allow-listed host")
	}
}

func TestIntegration_TLSDiagnose_PEMOptIn(t *testing.T) {
	client, addr, _, cleanup := newTLSTestServer(t)
	defer cleanup()
	port := parsePortFromAddr(t, addr)
	res, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "tls_diagnose",
		Arguments: map[string]any{
			"host":        "127.0.0.1",
			"port":        port,
			"include_pem": false,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected success: %+v", res.Content)
	}
	var out tlsdiag.Report
	b, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(b, &out)
	if out.Leaf.PEM != "" {
		t.Errorf("expected PEM empty when include_pem=false")
	}
}

func TestIntegration_TLSDiagnose_PEMOptIn_True(t *testing.T) {
	client, addr, _, cleanup := newTLSTestServer(t)
	defer cleanup()
	port := parsePortFromAddr(t, addr)
	res, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "tls_diagnose",
		Arguments: map[string]any{
			"host":        "127.0.0.1",
			"port":        port,
			"include_pem": true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected success: %+v", res.Content)
	}
	var out tlsdiag.Report
	b, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(b, &out)
	if out.Leaf.PEM == "" {
		t.Errorf("expected non-empty PEM when include_pem=true")
	}
	if !contains(out.Leaf.PEM, "BEGIN CERTIFICATE") {
		t.Errorf("expected PEM, got %q", out.Leaf.PEM[:40])
	}
}

func TestIntegration_TLSDiagnose_HostnameMismatch(t *testing.T) {
	// Connect to localhost but ask for a wrong SNI — the analyser
	// will report the mismatch as a critical finding.
	client, addr, _, cleanup := newTLSTestServer(t)
	defer cleanup()
	port := parsePortFromAddr(t, addr)
	res, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "tls_diagnose",
		Arguments: map[string]any{
			"host":        "127.0.0.1",
			"port":        port,
			"server_name": "wrong.example.org",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	// Either the handshake fails (likely, because of strict
	// verification against server_name) or the chain is reported
	// with a TLS_HOSTNAME_MISMATCH finding. Both are acceptable
	// outcomes; what we want to assert is that no false success is
	// produced.
	if res.IsError {
		return // server returned a structured error — also fine
	}
	var out tlsdiag.Report
	b, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(b, &out)
	if out.Handshake.Succeeded && out.Chain.HostnameMatches {
		t.Errorf("expected hostname mismatch to be detected")
	}
}

func TestIntegration_TLSDiagnose_EmptyHost(t *testing.T) {
	client, _, _, cleanup := newTLSTestServer(t)
	defer cleanup()

	res, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "tls_diagnose",
		Arguments: map[string]any{
			"host": "",
			"port": 443,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Errorf("expected IsError=true for empty host")
	}
}

func TestIntegration_TLSDiagnose_MinSeverity(t *testing.T) {
	client, addr, _, cleanup := newTLSTestServer(t)
	defer cleanup()
	port := parsePortFromAddr(t, addr)
	res, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "tls_diagnose",
		Arguments: map[string]any{
			"host":         "127.0.0.1",
			"port":         port,
			"min_severity": "critical",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected success: %+v", res.Content)
	}
	var out tlsdiag.Report
	b, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(b, &out)
	for _, f := range out.Findings {
		if f.Severity != tlsdiag.SeverityCritical {
			t.Errorf("finding %s has severity %s below filter", f.ID, f.Severity)
		}
	}
}

func TestIntegration_TLSDiagnose_ProbeProtocols(t *testing.T) {
	client, addr, _, cleanup := newTLSTestServer(t)
	defer cleanup()
	port := parsePortFromAddr(t, addr)
	res, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "tls_diagnose",
		Arguments: map[string]any{
			"host":            "127.0.0.1",
			"port":            port,
			"probe_protocols": true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected success: %+v", res.Content)
	}
	var out tlsdiag.Report
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Protocols == nil {
		t.Errorf("expected Protocols to be populated")
	} else if !out.Protocols.Probed {
		t.Errorf("expected Protocols.Probed=true")
	}
}

func TestIntegration_TLSDiagnose_Grade(t *testing.T) {
	client, addr, _, cleanup := newTLSTestServer(t)
	defer cleanup()
	port := parsePortFromAddr(t, addr)
	res, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "tls_diagnose",
		Arguments: map[string]any{
			"host": "127.0.0.1",
			"port": port,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	var out tlsdiag.Report
	b, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(b, &out)
	if out.Grade == "" {
		t.Errorf("expected non-empty grade on healthy report")
	}
	if out.Score < 0 || out.Score > 100 {
		t.Errorf("expected score in 0..100, got %d", out.Score)
	}
}

func TestIntegration_TLSDiagnose_AIAFetch_DisabledByConfig(t *testing.T) {
	client, addr, _, cleanup := newTLSTestServer(t)
	defer cleanup()
	port := parsePortFromAddr(t, addr)
	res, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "tls_diagnose",
		Arguments: map[string]any{
			"host":      "127.0.0.1",
			"port":      port,
			"aia_fetch": true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected success: %+v", res.Content)
	}
	var out tlsdiag.Report
	b, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(b, &out)
	found := false
	for _, s := range out.ChecksSkipped {
		if s.Check == "TLS_AIA_FETCH" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TLS_AIA_FETCH in ChecksSkipped when config disables it")
	}
}

// --- helpers ---

func parsePortFromAddr(t *testing.T, addr string) uint16 {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return uint16(p)
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
