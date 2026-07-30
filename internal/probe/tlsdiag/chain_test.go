package tlsdiag

import (
	"crypto/x509"
	"net"
	"testing"
)

func TestAnalyzeChain_Complete(t *testing.T) {
	leaf, inter, root, pool := buildChain(t, nil)
	now := testClock()
	rep := analyzeChain([]*x509.Certificate{leaf, inter, root}, "leaf.example.com", pool, now, false)
	if !rep.Complete {
		t.Errorf("expected complete chain, got %+v", rep)
	}
	if !rep.TrustedBySystem {
		t.Errorf("expected TrustedBySystem")
	}
	if !rep.Ordered {
		t.Errorf("expected ordered")
	}
	if !rep.RootIncluded {
		// The chain we built is leaf → intermediate → root, all three
		// presented; the root is included.
		t.Errorf("expected RootIncluded=true, got %+v", rep)
	}
	if rep.HostnameMatches != true {
		t.Errorf("expected hostname match")
	}
}

func TestAnalyzeChain_HostnameMismatch(t *testing.T) {
	leaf, inter, root, pool := buildChain(t, nil)
	now := testClock()
	rep := analyzeChain([]*x509.Certificate{leaf, inter, root}, "other.example.org", pool, now, false)
	if rep.HostnameMatches {
		t.Errorf("expected hostname mismatch")
	}
	// Even with a wrong hostname the chain itself is structurally
	// complete (the leaf matches a different name but the chain
	// verifies when the name constraint is dropped).
	if !rep.Complete {
		t.Errorf("chain without DNSName should still verify as Complete=true")
	}
}

func TestAnalyzeChain_Incomplete(t *testing.T) {
	// Build a leaf directly signed by a root, but only present the leaf
	// (no root in the chain).
	leaf, _, _, pool := buildChain(t, nil)
	now := testClock()
	rep := analyzeChain([]*x509.Certificate{leaf}, "leaf.example.com", pool, now, false)
	if rep.Complete {
		t.Errorf("expected incomplete chain when only leaf is presented")
	}
	if !rep.MissingIntermediate {
		// "unable to get local issuer certificate" or "unknown authority"
		// should have been detected.
		t.Errorf("expected MissingIntermediate=true, got %+v", rep)
	}
}

func TestAnalyzeChain_RootIncluded(t *testing.T) {
	leaf, inter, root, pool := buildChain(t, nil)
	now := testClock()
	rep := analyzeChain([]*x509.Certificate{leaf, inter, root}, "leaf.example.com", pool, now, false)
	// Length 3 with the last being self-signed → root IS included.
	if !rep.RootIncluded {
		t.Errorf("expected RootIncluded=true, got %+v", rep)
	}
}

func TestAnalyzeChain_Duplicate(t *testing.T) {
	leaf, inter, _, pool := buildChain(t, nil)
	now := testClock()
	rep := analyzeChain([]*x509.Certificate{leaf, inter, leaf}, "leaf.example.com", pool, now, false)
	if len(rep.ExtraneousCerts) == 0 {
		t.Errorf("expected extraneous certs from duplicate, got %+v", rep)
	}
}

func TestIsChainOrdered(t *testing.T) {
	leaf, inter, root, _ := buildChain(t, nil)
	if !isChainOrdered([]*x509.Certificate{leaf, inter, root}) {
		t.Errorf("expected ordered")
	}
	// Reversed → not ordered.
	if isChainOrdered([]*x509.Certificate{root, inter, leaf}) {
		t.Errorf("expected not ordered when reversed")
	}
}

func TestHostnameMatches(t *testing.T) {
	leaf, _, _, _ := buildChain(t, nil)
	if ok, name := hostnameMatches(leaf, "leaf.example.com"); !ok || name != "leaf.example.com" {
		t.Errorf("expected match leaf.example.com, got ok=%v name=%q", ok, name)
	}
	if ok, _ := hostnameMatches(leaf, "other.example.com"); ok {
		t.Errorf("expected mismatch")
	}
}

func TestHostnameMatches_Wildcard(t *testing.T) {
	mut := func(c *x509.Certificate) {
		c.DNSNames = []string{"*.example.com"}
	}
	leaf, _, _, _ := buildChain(t, mut)
	if ok, _ := hostnameMatches(leaf, "api.example.com"); !ok {
		t.Errorf("expected wildcard match for api.example.com")
	}
	if ok, _ := hostnameMatches(leaf, "evil.com"); ok {
		t.Errorf("expected wildcard NOT to match evil.com")
	}
	if ok, _ := hostnameMatches(leaf, "deep.api.example.com"); ok {
		t.Errorf("expected wildcard NOT to match deep.api.example.com (single-label rule)")
	}
}

func TestHostnameMatches_IP(t *testing.T) {
	mut := func(c *x509.Certificate) {
		c.DNSNames = nil
		c.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")}
	}
	leaf, _, _, _ := buildChain(t, mut)
	if ok, _ := hostnameMatches(leaf, "192.0.2.1"); !ok {
		t.Errorf("expected IP match")
	}
	if ok, _ := hostnameMatches(leaf, "198.51.100.1"); ok {
		t.Errorf("expected IP mismatch")
	}
}

func TestIsSelfSigned(t *testing.T) {
	leaf, _, root, _ := buildChain(t, nil)
	if isSelfSigned(leaf) {
		t.Errorf("leaf should not be self-signed")
	}
	if !isSelfSigned(root) {
		t.Errorf("root should be self-signed")
	}
}

func TestIsOnlyMissingIntermediate(t *testing.T) {
	if !isOnlyMissingIntermediate(errString("x509: certificate signed by unknown authority")) {
		t.Errorf("expected true for unknown authority")
	}
	if !isOnlyMissingIntermediate(errString("x509: unable to get local issuer certificate")) {
		t.Errorf("expected true for missing local issuer")
	}
	if isOnlyMissingIntermediate(errString("hostname mismatch")) {
		t.Errorf("expected false for hostname mismatch")
	}
}

func errString(s string) error { return &stringErr{s} }

type stringErr struct{ s string }

func (e *stringErr) Error() string { return e.s }
