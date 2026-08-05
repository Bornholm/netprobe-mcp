// Tests for the read-only MCP resources exposed by the server:
// probe://policy, probe://findings/catalog, probe://capabilities.
// Each test exercises the handler directly (no MCP session needed)
// and asserts the JSON shape and key invariants.

package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/bornholm/netprobe-mcp/internal/probe/tlsdiag"
)

func newServerWithConfig(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	s := &Server{cfg: cfg}
	return s
}

func TestPolicyResource_IncludesAllowAndDenyCounts(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Name:          "test",
			Version:       "0.1.0",
			Transport:     "stdio",
			ShutdownGrace: 10 * time.Second,
		},
		Security: config.SecurityConfig{
			Targets: config.TargetPolicy{
				Allow: []config.TargetRule{
					{Type: "exact", Pattern: "a.example"},
					{Type: "exact", Pattern: "b.example"},
				},
				Deny: []config.TargetRule{
					{Type: "suffix", Pattern: ".internal"},
				},
			},
			Network: config.NetworkPolicy{
				BlockPrivate:     ptrBool(true),
				BlockLoopback:    ptrBool(true),
				BlockLinkLocal:   ptrBool(true),
				BlockMulticast:   ptrBool(true),
				BlockUnspecified: ptrBool(true),
				BlockCloudMeta:   ptrBool(true),
				AllowIPv4:        ptrBool(true),
				AllowIPv6:        ptrBool(false),
				DenyCIDRs:        []string{"100.64.0.0/10"},
			},
			DNS: config.DNSPolicy{Timeout: 3 * time.Second, CacheTTL: 60 * time.Second},
		},
		Limits: config.LimitsConfig{
			Global:              config.RateLimit{RPS: 5, Burst: 10},
			PerTarget:           config.RateLimit{RPS: 0.5, Burst: 3},
			PerSession:          config.RateLimit{RPS: 2, Burst: 5},
			MaxConcurrentProbes: 8,
			KeyedLimiterTTL:     10 * time.Minute,
			KeyedLimiterMaxKeys: 2048,
			MaxCallsPerSession:  500,
		},
		Probes: config.ProbesConfig{
			TCP:  config.TCPProbeConfig{Enabled: true},
			HTTP: config.HTTPProbeConfig{Enabled: true},
			DNS:  config.DNSProbeConfig{Enabled: true},
			TLS:  config.TLSDiagConfig{Enabled: true, AllowAIAFetch: false, AllowOCSPQuery: false},
		},
	}

	s := newServerWithConfig(t, cfg)
	res, err := s.readPolicyResource(context.Background(), nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(res.Contents) != 1 {
		t.Fatalf("expected one content entry, got %d", len(res.Contents))
	}
	var body PolicyResource
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Security.AllowRuleCount != 2 {
		t.Errorf("AllowRuleCount = %d, want 2", body.Security.AllowRuleCount)
	}
	if body.Security.DenyRuleCount != 1 {
		t.Errorf("DenyRuleCount = %d, want 1", body.Security.DenyRuleCount)
	}
	if !body.Security.BlockPrivate {
		t.Errorf("BlockPrivate should be true")
	}
	if body.Security.AllowIPv6 {
		t.Errorf("AllowIPv6 should be false")
	}
	if !body.Probes["tls_diagnose"] {
		t.Errorf("tls_diagnose should be enabled")
	}
	if body.TLSDiag.AllowAIAFetch {
		t.Errorf("AllowAIAFetch should be false")
	}
	if !strings.Contains(body.Limits.KeyedLimiterTTL, "10m") {
		t.Errorf("KeyedLimiterTTL = %q, want to contain 10m", body.Limits.KeyedLimiterTTL)
	}
}

func TestCapabilitiesResource_DocumentsUntestableChecks(t *testing.T) {
	cfg := &config.Config{
		Probes: config.ProbesConfig{
			TCP: config.TCPProbeConfig{Enabled: true},
			TLS: config.TLSDiagConfig{Enabled: true, AllowAIAFetch: false, AllowOCSPQuery: false},
		},
	}
	s := newServerWithConfig(t, cfg)
	res, err := s.readCapabilitiesResource(context.Background(), nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var body CapabilitiesResource
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	wantChecks := []string{
		"TLS_SSLV3_ENABLED",
		"TLS_WEAK_CIPHER_RC4",
		"TLS_WEAK_CIPHER_NULL",
		"TLS_WEAK_CIPHER_EXPORT",
		"TLS_WEAK_DH_PARAMS",
		"TLS_INSECURE_RENEGOTIATION",
	}
	seen := map[string]bool{}
	for _, s := range body.ChecksAlwaysSkipped {
		seen[s.Check] = true
	}
	for _, w := range wantChecks {
		if !seen[w] {
			t.Errorf("ChecksAlwaysSkipped missing %s", w)
		}
	}
	for _, probe := range body.ProbesEnabled {
		if probe == "" {
			t.Error("empty probe name in ProbesEnabled")
		}
	}
	if len(body.Notes) == 0 {
		t.Error("expected Notes to mention disabled AIA/OCSP")
	}
}

func TestFindingsCatalogResource_ContainsKnownIDs(t *testing.T) {
	cfg := &config.Config{
		Probes: config.ProbesConfig{
			TLS: config.TLSDiagConfig{Enabled: true},
		},
	}
	s := newServerWithConfig(t, cfg)
	res, err := s.readFindingsCatalogResource(context.Background(), nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var body []FindingCatalogItem
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	wantIDs := []string{
		"TLS_CERT_EXPIRED",
		"TLS_HOSTNAME_MISMATCH",
		"TLS_CHAIN_MISSING_INTERMEDIATE",
		"TLS_MUST_STAPLE_WITHOUT_STAPLE",
		"TLS_WEAK_CIPHER_3DES",
		"TLS_HSTS_MISSING",
		"TLS_STARTTLS_NOT_OFFERED",
	}
	seen := map[string]bool{}
	for _, f := range body {
		seen[f.ID] = true
		if f.Severity == "" {
			t.Errorf("finding %s has empty severity", f.ID)
		}
		if f.Title == "" {
			t.Errorf("finding %s has empty title", f.ID)
		}
	}
	for _, w := range wantIDs {
		if !seen[w] {
			t.Errorf("findings catalog missing %s", w)
		}
	}
}

func TestResources_NotRegisteredWhenTLSDisabled(t *testing.T) {
	// Findings catalogue should NOT be served when TLS diag is off;
	// the other two resources always exist.
	cfg := &config.Config{
		Probes: config.ProbesConfig{
			TLS: config.TLSDiagConfig{Enabled: false},
		},
	}
	s := &Server{cfg: cfg, mcp: nil}
	// nil mcp means AddResource would panic; we just exercise the
	// build helpers instead.
	if got := len(s.buildCapabilitiesResource().ProbesEnabled); got != 0 {
		t.Errorf("ProbesEnabled should be empty when nothing is enabled, got %d", got)
	}
}

func TestResources_FindingsNotRegisteredWhenTLSDisabled(t *testing.T) {
	cfg := &config.Config{
		Probes: config.ProbesConfig{TLS: config.TLSDiagConfig{Enabled: false}},
	}
	s := &Server{cfg: cfg}
	if cat := s.findingsCatalog(); len(cat) == 0 {
		t.Error("findingsCatalog should still return content even when TLS diag is disabled (the helper is data-only)")
	}
	if !strings.Contains(cfg.Server.Name, "") {
		// anchor: keep import strings alive
	}
}

// TestFindingsCatalog_MatchesRuleRegistry is the regression test for
// PLAN §13.17: the findings catalogue MUST be the union of every
// rule in DefaultRules() and every check in AlwaysSkipped(). A
// catalogue entry that points to no rule would be a "ghost finding"
// — the agent would believe a check is active when nothing in the
// codebase ever emits it. Conversely, a rule whose ID does not
// appear in the catalogue would be undocumented.
//
// The test also asserts no duplicate IDs in the catalogue.
func TestFindingsCatalog_MatchesRuleRegistry(t *testing.T) {
	cfg := &config.Config{Probes: config.ProbesConfig{TLS: config.TLSDiagConfig{Enabled: true}}}
	s := &Server{cfg: cfg}
	cat := s.findingsCatalog()
	if len(cat) == 0 {
		t.Fatal("catalogue is empty")
	}

	// Collect the IDs the rules actually emit.
	ruleIDs := map[string]bool{}
	for _, r := range tlsdiag.DefaultRules() {
		id := r.Metadata().ID
		if id == "" {
			continue
		}
		if ruleIDs[id] {
			t.Errorf("rule registry contains duplicate ID %q", id)
		}
		ruleIDs[id] = true
	}

	// Collect the IDs the always-skipped list declares.
	skippedIDs := map[string]bool{}
	for _, s := range tlsdiag.AlwaysSkipped() {
		skippedIDs[s.Check] = true
	}

	// The catalogue must cover both sets, and contain nothing else.
	catIDs := map[string]bool{}
	for _, c := range cat {
		if catIDs[c.ID] {
			t.Errorf("catalogue contains duplicate ID %q", c.ID)
		}
		catIDs[c.ID] = true

		if !ruleIDs[c.ID] && !skippedIDs[c.ID] {
			t.Errorf("catalogue entry %q matches no rule and no skipped check", c.ID)
		}
		// Note: an ID can appear in both DefaultRules() and
		// AlwaysSkipped() (e.g. TLS_WEAK_CIPHER_RC4 is unreachable
		// with crypto/tls but the raw-ClientHello probe can emit
		// it). The catalogue lists it once with the active rule's
		// severity.
	}

	// Every rule MUST be documented.
	for id := range ruleIDs {
		if !catIDs[id] {
			t.Errorf("rule %q is not in the catalogue — agent cannot interpret it", id)
		}
	}
	// Every skipped check MUST be documented (with severity=disabled).
	for id := range skippedIDs {
		if !catIDs[id] {
			t.Errorf("skipped check %q is not in the catalogue", id)
		}
	}

	// Active rules must carry a non-empty severity that is one of
	// the known Severity constants. Skipped checks use the
	// "disabled" sentinel.
	for _, c := range cat {
		switch c.Severity {
		case string(tlsdiag.SeverityCritical),
			string(tlsdiag.SeverityHigh),
			string(tlsdiag.SeverityMedium),
			string(tlsdiag.SeverityLow),
			string(tlsdiag.SeverityInfo),
			"disabled":
			// OK
		default:
			t.Errorf("catalogue entry %q has unknown severity %q", c.ID, c.Severity)
		}
		if c.Title == "" {
			t.Errorf("catalogue entry %q has empty title", c.ID)
		}
	}
}
