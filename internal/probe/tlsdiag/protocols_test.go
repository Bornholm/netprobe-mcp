// Tests for the protocol enumeration active phase. The TLS server
// in startTLSServer uses tls.VersionTLS12 as its minimum, so we
// expect TLS 1.0 and 1.1 to be reported as not supported, TLS 1.2
// as supported, and TLS 1.3 as supported (the default Go listener
// accepts both 1.2 and 1.3).

package tlsdiag

import (
	"net/netip"
	"strconv"
	"testing"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

func TestProbeProtocols_Healthy(t *testing.T) {
	addr, pool, _ := startTLSServer(t)
	host, port := splitAddr(addr)
	tgt := &security.SafeTarget{
		Hostname: "localhost",
		IP:       netip.MustParseAddr(host),
		Port:     port,
		Scheme:   "tls",
	}
	a := analyzerStubWithDialer(t, pool)
	ps := a.probeProtocols(testContext(t), tgt)
	if !ps.Probed {
		t.Errorf("expected Probed=true")
	}
	if ps.SSLv30 != TriUnknown {
		t.Errorf("expected SSLv30=TriUnknown, got %s", ps.SSLv30)
	}
	if ps.TLS12 != TriYes {
		t.Errorf("expected TLS12=TriYes, got %s", ps.TLS12)
	}
	if ps.TLS13 != TriYes {
		t.Errorf("expected TLS13=TriYes, got %s", ps.TLS13)
	}
	if ps.TLS10 != TriNo {
		t.Errorf("expected TLS10=TriNo, got %s", ps.TLS10)
	}
	if ps.TLS11 != TriNo {
		t.Errorf("expected TLS11=TriNo, got %s", ps.TLS11)
	}
}

func TestProbeProtocols_CancelledContext(t *testing.T) {
	addr, pool, _ := startTLSServer(t)
	host, port := splitAddr(addr)
	tgt := &security.SafeTarget{
		Hostname: "localhost",
		IP:       netip.MustParseAddr(host),
		Port:     port,
		Scheme:   "tls",
	}
	a := analyzerStubWithDialer(t, pool)
	ctx, cancel := testCancelledContext()
	ps := a.probeProtocols(ctx, tgt)
	// Cancelled mid-probe: at least one version reported as
	// not_tested because the global budget is exhausted.
	if ps.TLS12 == TriYes || ps.TLS13 == TriYes {
		t.Errorf("expected some TriUnknown after cancel, got %+v", ps)
	}
	_ = cancel
}

func TestProbeProtocols_RunsThroughRunOptionalPhases(t *testing.T) {
	addr, pool, _ := startTLSServer(t)
	host, port := splitAddr(addr)
	tgt := &security.SafeTarget{
		Hostname: "localhost",
		IP:       netip.MustParseAddr(host),
		Port:     port,
		Scheme:   "tls",
	}
	a := analyzerStubWithDialer(t, pool)
	rep, err := a.Diagnose(tgt, DiagnoseOptions{ProbeProtocols: true})
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if rep.Protocols == nil {
		t.Fatalf("expected Protocols to be populated when ProbeProtocols=true")
	}
	if !rep.Protocols.Probed {
		t.Errorf("expected Probed=true")
	}
	// TLS_PROTOCOLS_ENUM must be removed from ChecksSkipped once
	// the phase has actually run.
	for _, s := range rep.ChecksSkipped {
		if s.Check == "TLS_PROTOCOLS_ENUM" {
			t.Errorf("expected TLS_PROTOCOLS_ENUM to be removed after run, got reason=%q", s.Reason)
		}
	}
}

func TestProbeProtocols_NotEnabled(t *testing.T) {
	addr, pool, _ := startTLSServer(t)
	host, port := splitAddr(addr)
	tgt := &security.SafeTarget{
		Hostname: "localhost",
		IP:       netip.MustParseAddr(host),
		Port:     port,
		Scheme:   "tls",
	}
	a := analyzerStubWithDialer(t, pool)
	rep, err := a.Diagnose(tgt, DiagnoseOptions{})
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if rep.Protocols != nil {
		t.Errorf("expected Protocols=nil when ProbeProtocols=false")
	}
	found := false
	for _, s := range rep.ChecksSkipped {
		if s.Check == "TLS_PROTOCOLS_ENUM" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected TLS_PROTOCOLS_ENUM in ChecksSkipped when not run")
	}
	_ = strconv.Itoa // keep strconv reference if test changes
}
