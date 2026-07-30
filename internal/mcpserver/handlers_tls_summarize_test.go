package mcpserver

import (
	"strings"
	"testing"

	"github.com/bornholm/netprobe-mcp/internal/probe/tlsdiag"
)

// TestSummarizeTLS_EvidenceTriggeredChainMissingIntermediate ensures that
// the chain/leaf evidence block is emitted when TLS_CHAIN_MISSING_INTERMEDIATE
// is reported and includes the AIA URL that points to the missing cert.
func TestSummarizeTLS_EvidenceTriggeredChainMissingIntermediate(t *testing.T) {
	rep := &tlsdiag.Report{
		Target:  tlsdiag.TargetInfo{Host: "smtp.cadoles.com"},
		Grade:   "D",
		Score:   69,
		Verdict: "TLS configuration has high-severity issues",
		Chain: tlsdiag.ChainReport{
			Length:              1,
			Complete:            false,
			Ordered:             true,
			MissingIntermediate: true,
		},
		Leaf: tlsdiag.CertReport{
			Subject:            "CN=*.cadoles.com",
			Issuer:             "CN=R10, O=Let's Encrypt",
			PublicKeyAlgorithm: "RSA",
			PublicKeyBits:      2048,
			SignatureAlgorithm: "SHA256-RSA",
			DNSNames:           []string{"*.cadoles.com", "cadoles.com"},
			IssuingCertURLs:    []string{"http://r10.i.lencr.org/"},
		},
		Findings: []tlsdiag.Finding{
			{ID: "TLS_CHAIN_MISSING_INTERMEDIATE", Severity: tlsdiag.SeverityHigh, Category: "chain"},
		},
	}
	out := summarizeTLS(rep)

	if !strings.Contains(out, "[chain]") {
		t.Errorf("expected [chain] block, got:\n%s", out)
	}
	if !strings.Contains(out, "presented=1") {
		t.Errorf("expected presented=1, got:\n%s", out)
	}
	if !strings.Contains(out, "complete=false") {
		t.Errorf("expected complete=false, got:\n%s", out)
	}
	if !strings.Contains(out, "aia_ca_issuer=http://r10.i.lencr.org/") {
		t.Errorf("expected aia_ca_issuer URL, got:\n%s", out)
	}
	if !strings.Contains(out, "[leaf]") {
		t.Errorf("expected [leaf] block, got:\n%s", out)
	}
	if !strings.Contains(out, "key=RSA-2048") {
		t.Errorf("expected key=RSA-2048, got:\n%s", out)
	}
	if !strings.Contains(out, "sig=SHA256-RSA") {
		t.Errorf("expected sig=SHA256-RSA, got:\n%s", out)
	}
	if !strings.Contains(out, `subject="CN=*.cadoles.com"`) {
		t.Errorf("expected subject quoted, got:\n%s", out)
	}
}

// TestSummarizeTLS_EvidenceTriggeredWildcardTooBroad ensures that the SAN
// wildcard list is surfaced when TLS_WILDCARD_TOO_BROAD fires, but no
// non-wildcard SAN leaks into the summary.
func TestSummarizeTLS_EvidenceTriggeredWildcardTooBroad(t *testing.T) {
	rep := &tlsdiag.Report{
		Target: tlsdiag.TargetInfo{Host: "example.com"},
		Chain:  tlsdiag.ChainReport{Length: 1, Complete: true, Ordered: true},
		Leaf: tlsdiag.CertReport{
			DNSNames: []string{"*.example.com", "example.com", "mail.example.com"},
		},
		Findings: []tlsdiag.Finding{
			{ID: "TLS_WILDCARD_TOO_BROAD", Severity: tlsdiag.SeverityMedium, Category: "identity"},
		},
	}
	out := summarizeTLS(rep)

	if !strings.Contains(out, "san_wildcards=[*.example.com]") {
		t.Errorf("expected san_wildcards=[*.example.com], got:\n%s", out)
	}
	if strings.Contains(out, "mail.example.com") {
		t.Errorf("non-wildcard SAN leaked into summary: %s", out)
	}
	if strings.Contains(out, "example.com,") || strings.Contains(out, ",example.com") {
		t.Errorf("non-wildcard SAN leaked into summary: %s", out)
	}
}

// TestSummarizeTLS_NoEvidenceOnHealthy ensures the chain/leaf block is
// omitted entirely when no trigger fires. The summary stays compact for
// successful probes.
func TestSummarizeTLS_NoEvidenceOnHealthy(t *testing.T) {
	rep := &tlsdiag.Report{
		Target: tlsdiag.TargetInfo{Host: "api.example.com"},
		Chain:  tlsdiag.ChainReport{Length: 2, Complete: true, Ordered: true},
		Leaf:   tlsdiag.CertReport{PublicKeyAlgorithm: "RSA", PublicKeyBits: 2048},
		Findings: []tlsdiag.Finding{
			{ID: "TLS_HSTS_HEADER_MISSING", Severity: tlsdiag.SeverityLow, Category: "config"},
		},
	}
	out := summarizeTLS(rep)

	if strings.Contains(out, "[chain]") {
		t.Errorf("expected no [chain] block on healthy probe, got:\n%s", out)
	}
	if strings.Contains(out, "[leaf]") {
		t.Errorf("expected no [leaf] block on healthy probe, got:\n%s", out)
	}
}

// TestSummarizeTLS_FullExampleOnRealWorld reproduces the output format
// for the exact report shape observed on smtp.cadoles.com:465 and dumps
// it so a reviewer can confirm the evidence block renders correctly.
func TestSummarizeTLS_FullExampleOnRealWorld(t *testing.T) {
	rep := &tlsdiag.Report{
		Target:  tlsdiag.TargetInfo{Host: "smtp.cadoles.com"},
		Grade:   "D",
		Score:   69,
		Verdict: "TLS configuration has high-severity issues — review before renewal",
		Summary: tlsdiag.FindingCounts{Critical: 0, High: 1, Medium: 1, Low: 1, Info: 0},
		Handshake: tlsdiag.HandshakeInfo{
			Succeeded:   true,
			Version:     "TLS 1.3",
			CipherSuite: "TLS_AES_128_GCM_SHA256",
		},
		Chain: tlsdiag.ChainReport{
			Length:              1,
			Complete:            false,
			Ordered:             true,
			MissingIntermediate: true,
		},
		Leaf: tlsdiag.CertReport{
			Subject:            "CN=*.cadoles.com",
			Issuer:             "CN=R10, O=Let's Encrypt",
			PublicKeyAlgorithm: "RSA",
			PublicKeyBits:      2048,
			SignatureAlgorithm: "SHA256-RSA",
			DNSNames:           []string{"*.cadoles.com", "cadoles.com"},
			IssuingCertURLs:    []string{"http://r10.i.lencr.org/"},
		},
		Findings: []tlsdiag.Finding{
			{ID: "TLS_CHAIN_MISSING_INTERMEDIATE", Severity: tlsdiag.SeverityHigh, Category: "chain", Title: "Incomplete certificate chain: intermediate CA not served"},
			{ID: "TLS_WILDCARD_TOO_BROAD", Severity: tlsdiag.SeverityMedium, Category: "identity", Title: "Broad wildcard certificate"},
			{ID: "TLS_SUBOPTIMAL_RSA_KEY", Severity: tlsdiag.SeverityLow, Category: "crypto", Title: "RSA key is at the minimum recommended size"},
		},
	}
	out := summarizeTLS(rep)
	t.Logf("summary output:\n%s", out)

	if !strings.Contains(out, "[chain] presented=1 complete=false ordered=true aia_ca_issuer=http://r10.i.lencr.org/") {
		t.Errorf("chain block incomplete:\n%s", out)
	}
	if !strings.Contains(out, "[leaf]  key=RSA-2048 sig=SHA256-RSA san_wildcards=[*.cadoles.com] subject=\"CN=*.cadoles.com\"") {
		t.Errorf("leaf block incomplete:\n%s", out)
	}
}

// TestSummarizeTLS_HostnameMismatch surfaces the matched SAN when the
// hostname verification finding fires, so the agent can see what name the
// server actually presented.
func TestSummarizeTLS_HostnameMismatch(t *testing.T) {
	rep := &tlsdiag.Report{
		Target: tlsdiag.TargetInfo{Host: "wrong.example.org"},
		Chain: tlsdiag.ChainReport{
			Length:          1,
			Complete:        true,
			Ordered:         true,
			HostnameMatches: false,
			MatchedName:     "*.cadoles.com",
		},
		Leaf: tlsdiag.CertReport{
			DNSNames: []string{"*.cadoles.com", "cadoles.com"},
		},
		Findings: []tlsdiag.Finding{
			{ID: "TLS_HOSTNAME_MISMATCH", Severity: tlsdiag.SeverityCritical, Category: "identity"},
		},
	}
	out := summarizeTLS(rep)

	if !strings.Contains(out, `matched="*.cadoles.com"`) {
		t.Errorf("expected matched SAN, got:\n%s", out)
	}
}
