package tlsdiag

import (
	"crypto/tls"
	"crypto/x509"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

func TestAnalyzer_Diagnose_Healthy(t *testing.T) {
	addr, pool, _ := startTLSServer(t)
	host, port := splitAddr(addr)
	tgt := &security.SafeTarget{
		Hostname: "localhost",
		IP:       netip.MustParseAddr(host),
		Port:     port,
		Scheme:   "tls",
	}
	a := analyzerStubWithDialer(t, pool)
	rep, err := a.Diagnose(tgt, DiagnoseOptions{IncludePEM: false})
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if !rep.Handshake.Succeeded {
		t.Fatalf("handshake failed: %s", rep.Handshake.FailureReason)
	}
	if !rep.Chain.Complete {
		t.Errorf("expected complete chain, got %+v", rep.Chain)
	}
	if !rep.Chain.HostnameMatches {
		t.Errorf("expected hostname match")
	}
	if rep.Leaf.PEM != "" {
		t.Errorf("PEM should be empty when include_pem=false")
	}
	if len(rep.Chain.PresentedCerts) > 0 && rep.Chain.PresentedCerts[0].PEM != "" {
		t.Errorf("chain PEM should be empty when include_pem=false")
	}
}

func TestAnalyzer_Diagnose_WithPEM(t *testing.T) {
	addr, pool, _ := startTLSServer(t)
	host, port := splitAddr(addr)
	tgt := &security.SafeTarget{
		Hostname: "localhost",
		IP:       netip.MustParseAddr(host),
		Port:     port,
		Scheme:   "tls",
	}
	a := analyzerStubWithDialer(t, pool)
	rep, err := a.Diagnose(tgt, DiagnoseOptions{IncludePEM: true})
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if !strings.Contains(rep.Leaf.PEM, "BEGIN CERTIFICATE") {
		t.Errorf("expected PEM in leaf, got %q", rep.Leaf.PEM[:40])
	}
}

func TestAnalyzer_Diagnose_NilDialer(t *testing.T) {
	a := analyzerStub(nil)
	a.cfg.Dialer = nil
	tgt := safeTargetStub("localhost")
	_, err := a.Diagnose(tgt, DiagnoseOptions{})
	if err == nil {
		t.Errorf("expected error when dialer is nil")
	}
}

func TestAnalyzer_Diagnose_NilAnalyzer(t *testing.T) {
	var a *Analyzer
	_, err := a.Diagnose(safeTargetStub("localhost"), DiagnoseOptions{})
	if err == nil {
		t.Errorf("expected error when analyser is nil")
	}
}

func TestAnalyzer_Diagnose_NilTarget(t *testing.T) {
	a := analyzerStub(nil)
	a.cfg.Dialer = mustDialer(t, nil)
	_, err := a.Diagnose(nil, DiagnoseOptions{})
	if err == nil {
		t.Errorf("expected error when target is nil")
	}
}

func TestAnalyzer_Diagnose_MinSeverityFilter(t *testing.T) {
	addr, pool, _ := startTLSServer(t)
	host, port := splitAddr(addr)
	tgt := &security.SafeTarget{
		Hostname: "localhost",
		IP:       netip.MustParseAddr(host),
		Port:     port,
		Scheme:   "tls",
	}
	a := analyzerStubWithDialer(t, pool)
	rep, err := a.Diagnose(tgt, DiagnoseOptions{MinSeverity: string(SeverityHigh)})
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	for _, f := range rep.Findings {
		if !f.Severity.AtLeastAsSevere(SeverityHigh) {
			t.Errorf("finding %s has severity %s below filter", f.ID, f.Severity)
		}
	}
}

func TestAnalyzer_Diagnose_VerdictForCleanReport(t *testing.T) {
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
	if rep.Summary.Critical > 0 {
		t.Errorf("expected no critical findings on a healthy report")
	}
}

func TestAnalyzer_Disabled(t *testing.T) {
	a := NewAnalyzer(Config{Enabled: false})
	if a != nil {
		t.Errorf("expected nil analyser when disabled")
	}
}

func TestAnalyzer_SetRootCAs_Nil(t *testing.T) {
	var a *Analyzer
	a.SetRootCAs(nil) // should not panic
}

// --- helpers ---

// analyzerStubWithDialer builds an Analyzer with a real SafeDialer.
// This is the variant used by the end-to-end tests; the bare
// analyzerStub is reserved for tests that exercise pure helpers.
func analyzerStubWithDialer(t *testing.T, pool *x509.CertPool) *Analyzer {
	t.Helper()
	cfg := Config{
		Enabled:               true,
		TotalBudget:           5 * time.Second,
		HandshakeTimeout:      2 * time.Second,
		MinTLSVersion:         tls.VersionTLS12,
		MaxTLSVersion:         tls.VersionTLS13,
		ExpiringSoonDays:      30,
		ExpiringCriticalDays:  7,
		MaxValidityDays:       398,
		ExcessiveValidityDays: 825,
		MinRSAKeyBits:         2048,
		MinECKeyBits:          256,
		Roots:                 pool,
		Now:                   testNow(),
		Dialer:                mustDialer(t, pool),
	}
	return NewAnalyzer(cfg)
}

// analyzerStubWithGuard is like analyzerStubWithDialer but additionally
// wires a real Guard into the analyzer. Used by tests that need the
// secondary SSRF paths (AIA/OCSP) to be evaluated against an explicit
// allow-list — typically a deny-by-default one to exercise the refusal
// recording.
func analyzerStubWithGuard(t *testing.T, pool *x509.CertPool, g *security.Guard) *Analyzer {
	t.Helper()
	cfg := Config{
		Enabled:               true,
		TotalBudget:           5 * time.Second,
		HandshakeTimeout:      2 * time.Second,
		MinTLSVersion:         tls.VersionTLS12,
		MaxTLSVersion:         tls.VersionTLS13,
		ExpiringSoonDays:      30,
		ExpiringCriticalDays:  7,
		MaxValidityDays:       398,
		ExcessiveValidityDays: 825,
		MinRSAKeyBits:         2048,
		MinECKeyBits:          256,
		Roots:                 pool,
		Now:                   testNow(),
		Dialer:                mustDialer(t, pool),
		Guard:                 g,
	}
	return NewAnalyzer(cfg)
}

func splitAddr(addr string) (string, uint16) {
	host, portStr, err := splitHostPort(addr)
	if err != nil {
		panic(err)
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		panic(err)
	}
	return host, uint16(p)
}
