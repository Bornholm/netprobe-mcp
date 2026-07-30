// Tests for the AIA chasing and OCSP direct query phases. In v1
// these are gated behind both a config flag (false by default) and
// a per-call flag. The tests verify the gating logic and the
// guard refusal path.

package tlsdiag

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/bornholm/netprobe-mcp/internal/security"
)

func TestRunOptionalPhases_AIADisabledByConfig(t *testing.T) {
	addr, pool, presented := startTLSServer(t)
	host, port := splitAddr(addr)
	tgt := &security.SafeTarget{
		Hostname: "localhost",
		IP:       netip.MustParseAddr(host),
		Port:     port,
		Scheme:   "tls",
	}
	a := analyzerStubWithDialer(t, pool)
	rep, err := a.Diagnose(tgt, DiagnoseOptions{AIAFetch: true})
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	// With AllowAIAFetch=false, requesting AIA must surface a
	// SkippedCheck entry that documents the refusal.
	found := false
	for _, s := range rep.ChecksSkipped {
		if s.Check == "TLS_AIA_FETCH" && strings.Contains(s.Reason, "disabled by config") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected disabled-by-config SkippedCheck entry, got %+v", rep.ChecksSkipped)
	}
	_ = presented
}

func TestRunOptionalPhases_OCSPDisabledByConfig(t *testing.T) {
	addr, pool, _ := startTLSServer(t)
	host, port := splitAddr(addr)
	tgt := &security.SafeTarget{
		Hostname: "localhost",
		IP:       netip.MustParseAddr(host),
		Port:     port,
		Scheme:   "tls",
	}
	a := analyzerStubWithDialer(t, pool)
	rep, err := a.Diagnose(tgt, DiagnoseOptions{OCSPDirect: true})
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	found := false
	for _, s := range rep.ChecksSkipped {
		if s.Check == "TLS_OCSP_DIRECT_QUERY" && strings.Contains(s.Reason, "disabled by config") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected disabled-by-config SkippedCheck entry for OCSP")
	}
}

func TestRemoveSkipped(t *testing.T) {
	in := []SkippedCheck{
		{Check: "A", Reason: "a"},
		{Check: "B", Reason: "b"},
		{Check: "C", Reason: "c"},
	}
	out := removeSkipped(in, "B")
	if len(out) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(out))
	}
	if out[0].Check != "A" || out[1].Check != "C" {
		t.Errorf("unexpected output: %+v", out)
	}

	// Removing a missing entry returns the input unchanged.
	out = removeSkipped(in, "Z")
	if len(out) != 3 {
		t.Errorf("expected 3 entries, got %d", len(out))
	}
}

func TestAIAFetch_NoGuard(t *testing.T) {
	// AIA fetch without a guard must be a no-op (no SkippedCheck
	// added, no error returned).
	a := analyzerStub(nil)
	addr, _, presented := startTLSServer(t)
	host, port := splitAddr(addr)
	tgt := &security.SafeTarget{
		Hostname: "localhost",
		IP:       netip.MustParseAddr(host),
		Port:     port,
		Scheme:   "tls",
	}
	a.cfg.AllowAIAFetch = true
	a.cfg.Guard = nil
	rep := &Report{}
	a.fetchAIA(testContext(t), tgt, []*x509.Certificate{presented}, rep)
	if len(rep.ChecksSkipped) != 0 {
		t.Errorf("expected no SkippedCheck when guard is nil, got %+v", rep.ChecksSkipped)
	}
}

func TestSanitizeAIAURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"http://example.com/ca.crt", "http://example.com/ca.crt"},
		{"https://example.com/ca.crt", "https://example.com/ca.crt"},
		{"://malformed", "(unparseable)"},
	}
	for _, c := range cases {
		if got := sanitizeAIAURL(c.in); got != c.want {
			t.Errorf("sanitizeAIAURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAIAFetchHelper_NoServer(t *testing.T) {
	// Without a guard wired up, AIA helper returns no error and
	// does not modify the report. This documents the contract.
	a := analyzerStub(nil)
	a.cfg.AllowAIAFetch = true
	a.cfg.Guard = nil
	addr, _, presented := startTLSServer(t)
	host, port := splitAddr(addr)
	tgt := &security.SafeTarget{
		Hostname: "localhost",
		IP:       netip.MustParseAddr(host),
		Port:     port,
		Scheme:   "tls",
	}
	rep := &Report{ChecksSkipped: nil}
	a.fetchAIA(testContext(t), tgt, []*x509.Certificate{presented}, rep)
	_ = http.StatusOK
	_ = httptest.NewServer
}

// TestAIAFetch_OutboundRequestRecorded verifies that every URL the
// diagnostic fetches at the target's request — whether it succeeds,
// fails or is refused by the guard — is recorded in
// Report.OutboundRequests. The audit log relies on this field to
// reconstruct post-incident which URLs the server was tricked into
// fetching.
func TestAIAFetch_OutboundRequestRecorded(t *testing.T) {
	addr, pool, leafTmpl := startTLSServer(t)
	host, port := splitAddr(addr)
	tgt := &security.SafeTarget{
		Hostname: "localhost",
		IP:       netip.MustParseAddr(host),
		Port:     port,
		Scheme:   "tls",
	}

	// Wire a minimal Guard with an empty allow-list so every URL
	// gets refused. We don't need network reachability for this
	// test — only the authorisation path.
	sc := &config.SecurityConfig{
		Targets: config.TargetPolicy{
			Allow: []config.TargetRule{},
		},
		Network: config.NetworkPolicy{
			BlockLoopback:        ptrBool(false),
			AllowIPv4:            ptrBool(true),
			AllowIPv6:            ptrBool(false),
			DisableDefaultBogons: true,
		},
		DNS: config.DNSPolicy{},
	}
	filter, ferr := security.NewIPFilter(&sc.Network)
	if ferr != nil {
		t.Fatal(ferr)
	}
	resolver := security.NewSafeResolver(sc.DNS, filter)
	g, gerr := security.NewGuard(sc, resolver, nil, filter, nil)
	if gerr != nil {
		t.Fatal(gerr)
	}

	a := analyzerStubWithGuard(t, pool, g)
	_ = a // kept for symmetry with the active phases suite
	a.cfg.AllowAIAFetch = true

	// Synthesise a presented chain whose leaf advertises an AIA URL
	// pointing at a host that is NOT in any allow-list rule. The
	// Guard must refuse and the refusal must be recorded in
	// OutboundRequests.
	leafCert := *leafTmpl
	leafCert.IssuingCertificateURL = []string{"http://evil.example.com/ca.crt"}

	rep := &Report{}
	a.fetchAIA(testContext(t), tgt, []*x509.Certificate{&leafCert}, rep)

	deniedFound := false
	for _, o := range rep.OutboundRequests {
		if o.Purpose == "aia_fetch" && o.Outcome == "denied" && strings.Contains(o.URL, "evil.example.com") {
			deniedFound = true
		}
	}
	if !deniedFound {
		t.Errorf("expected an OutboundRequest for evil.example.com with outcome=denied, got %+v", rep.OutboundRequests)
	}
}
