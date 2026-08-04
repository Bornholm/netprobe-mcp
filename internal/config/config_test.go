package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefault_Validates(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("Default().Validate() = %v, want nil", err)
	}
}

func TestDefault_BlocksPrivateNetwork(t *testing.T) {
	c := Default()
	if !c.Security.Network.PrivateBlocked() {
		t.Errorf("default must block private networks")
	}
	if !c.Security.Network.CloudMetaBlocked() {
		t.Errorf("default must block cloud metadata IP")
	}
	if !c.Security.Network.LinkLocalBlocked() {
		t.Errorf("default must block link-local")
	}
	if !c.Security.Network.MulticastBlocked() {
		t.Errorf("default must block multicast")
	}
	if !c.Security.Network.UnspecifiedBlocked() {
		t.Errorf("default must block unspecified")
	}
}

func TestDefault_AllowsPublicDiagnostics(t *testing.T) {
	c := Default()
	if len(c.Security.Targets.Allow) == 0 {
		t.Fatal("default must declare at least one allow rule")
	}
	hasLoopback := false
	hasExample := false
	for _, r := range c.Security.Targets.Allow {
		if r.Type == "cidr" && r.Pattern == "127.0.0.0/8" {
			hasLoopback = true
		}
		if r.Type == "suffix" && r.Pattern == "example.com" {
			hasExample = true
		}
	}
	if !hasLoopback {
		t.Errorf("default allow-list must include 127.0.0.0/8")
	}
	if !hasExample {
		t.Errorf("default allow-list must include example.com")
	}
}

func TestDefault_SecondarySSRFChannelsOff(t *testing.T) {
	c := Default()
	if c.Probes.TLS.AllowAIAFetch {
		t.Errorf("default must keep AIA fetch off")
	}
	if c.Probes.TLS.AllowOCSPQuery {
		t.Errorf("default must keep OCSP query off")
	}
	if c.Probes.DNS.AllowDoT {
		t.Errorf("default must keep DNS-over-TLS off")
	}
	if c.Probes.DNS.AllowSystemResolver {
		t.Errorf("default must keep system resolver off")
	}
}

func TestDefault_AuditEnabled(t *testing.T) {
	c := Default()
	if !c.Audit.Enabled {
		t.Errorf("default must have audit enabled")
	}
}

func TestLoad_EmptyReturnsDefault(t *testing.T) {
	got, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") = %v, want nil", err)
	}
	want := Default()
	if len(got.Security.Targets.Allow) != len(want.Security.Targets.Allow) {
		t.Errorf("Load(\"\") allow-list length = %d, want %d",
			len(got.Security.Targets.Allow), len(want.Security.Targets.Allow))
	}
}

func TestLoad_FileMissing(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist.yaml")
	if _, err := Load(missing); err == nil {
		t.Errorf("Load(missing) = nil, want error")
	}
}

func TestLoad_PartialFileValidates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "minimal.yaml")
	// Empty YAML is valid: Validate fills in defaults for every
	// zero-valued field except security.targets.allow which must be
	// declared explicitly. We include just one allow rule.
	contents := `
limits:
  global: { rps: 1, burst: 1 }
security:
  targets:
    allow:
      - type: cidr
        pattern: "127.0.0.0/8"
        tools: ["tcp_probe"]
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load(partial) = %v, want nil", err)
	}
	if c.Server.Transport != "stdio" {
		t.Errorf("partial file should pick up default transport, got %q", c.Server.Transport)
	}
	if c.Probes.DefaultTimeout == 0 {
		t.Errorf("partial file should pick up default probe timeout")
	}
}

func TestLoad_RejectsEmptyAllowList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(path, []byte("server:\n  transport: stdio\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Errorf("Load(empty allow) = nil, want error (deny-by-default requires an allow rule)")
	}
}

func TestApplyFlagAllowRules_HostnameExact(t *testing.T) {
	c := Default()
	n, err := ApplyFlagAllowRules(c, []string{"foo.example.com"}, nil)
	if err != nil {
		t.Fatalf("ApplyFlagAllowRules = %v, want nil", err)
	}
	if n != 1 {
		t.Errorf("added = %d, want 1", n)
	}
	// Last allow rule is the flag-derived one.
	got := c.Security.Targets.Allow[len(c.Security.Targets.Allow)-1]
	if got.Type != "exact" || got.Pattern != "foo.example.com" {
		t.Errorf("rule = %+v, want exact foo.example.com", got)
	}
	if got.Comment == "" {
		t.Errorf("flag-derived rule must carry a comment")
	}
}

func TestApplyFlagAllowRules_HostnameSuffix(t *testing.T) {
	c := Default()
	n, err := ApplyFlagAllowRules(c, []string{".example.com"}, nil)
	if err != nil {
		t.Fatalf("ApplyFlagAllowRules = %v, want nil", err)
	}
	if n != 1 {
		t.Errorf("added = %d, want 1", n)
	}
	got := c.Security.Targets.Allow[len(c.Security.Targets.Allow)-1]
	if got.Type != "suffix" || got.Pattern != "example.com" {
		t.Errorf("rule = %+v, want suffix example.com", got)
	}
}

func TestApplyFlagAllowRules_CIDR(t *testing.T) {
	c := Default()
	n, err := ApplyFlagAllowRules(c, nil, []string{"10.0.0.0/8", "192.168.0.0/16"})
	if err != nil {
		t.Fatalf("ApplyFlagAllowRules = %v, want nil", err)
	}
	if n != 2 {
		t.Errorf("added = %d, want 2", n)
	}
	last := c.Security.Targets.Allow[len(c.Security.Targets.Allow)-2]
	if last.Type != "cidr" || last.Pattern != "10.0.0.0/8" {
		t.Errorf("rule = %+v, want cidr 10.0.0.0/8", last)
	}
	last = c.Security.Targets.Allow[len(c.Security.Targets.Allow)-1]
	if last.Type != "cidr" || last.Pattern != "192.168.0.0/16" {
		t.Errorf("rule = %+v, want cidr 192.168.0.0/16", last)
	}
}

func TestApplyFlagAllowRules_RejectsBadCIDR(t *testing.T) {
	c := Default()
	if _, err := ApplyFlagAllowRules(c, nil, []string{"not-a-cidr"}); err == nil {
		t.Errorf("bad CIDR accepted, want error")
	}
}

func TestApplyFlagAllowRules_RejectsEmptySuffix(t *testing.T) {
	c := Default()
	if _, err := ApplyFlagAllowRules(c, []string{"."}, nil); err == nil {
		t.Errorf("empty suffix accepted, want error")
	}
}

func TestApplyFlagAllowRules_RejectsSuffixNoDot(t *testing.T) {
	c := Default()
	if _, err := ApplyFlagAllowRules(c, []string{".nodot"}, nil); err == nil {
		t.Errorf("suffix without dot accepted, want error")
	}
}

func TestApplyFlagAllowRules_AcceptsIPv6(t *testing.T) {
	c := Default()
	n, err := ApplyFlagAllowRules(c, nil, []string{"2001:db8::/32"})
	if err != nil {
		t.Fatalf("ApplyFlagAllowRules = %v, want nil", err)
	}
	if n != 1 {
		t.Errorf("added = %d, want 1", n)
	}
}

func TestApplyFlagAllowRules_IgnoresEmpty(t *testing.T) {
	c := Default()
	before := len(c.Security.Targets.Allow)
	n, err := ApplyFlagAllowRules(c, []string{"", "  "}, []string{"", "  "})
	if err != nil {
		t.Fatalf("ApplyFlagAllowRules = %v, want nil", err)
	}
	if n != 0 {
		t.Errorf("added = %d, want 0", n)
	}
	if len(c.Security.Targets.Allow) != before {
		t.Errorf("allow-list length changed: before=%d, after=%d", before, len(c.Security.Targets.Allow))
	}
}

func TestApplyFlagAllowRules_ToolsCoverAllProbes(t *testing.T) {
	c := Default()
	if _, err := ApplyFlagAllowRules(c, []string{"foo.example.com"}, []string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("ApplyFlagAllowRules = %v, want nil", err)
	}
	want := map[string]bool{
		"tcp_probe":          true,
		"http_probe":         true,
		"dns_probe":          true,
		"tls_diagnose":       true,
		"icmp_probe":         true,
		"probe_check_target": true,
	}
	for _, r := range c.Security.Targets.Allow[len(c.Security.Targets.Allow)-2:] {
		got := map[string]bool{}
		for _, tool := range r.Tools {
			got[tool] = true
		}
		for tool := range want {
			if !got[tool] {
				t.Errorf("rule %q missing tool %q", r.Pattern, tool)
			}
		}
	}
}

// --- HTTP transport validation ---

func TestValidate_HTTPTransport_RequiresAuth(t *testing.T) {
	c := Default()
	c.Server.Transport = "http"
	// Auth intentionally left unconfigured.
	err := c.Validate()
	if err == nil {
		t.Fatalf("HTTP transport without auth: Validate() = nil, want error")
	}
	if !strings.Contains(err.Error(), "auth") {
		t.Errorf("expected error to mention auth, got %q", err)
	}
}

func TestValidate_HTTPTransport_BadTokenHash(t *testing.T) {
	c := Default()
	c.Server.Transport = "http"
	c.Server.HTTPConfig.Auth.TokenBearer.Enabled = true
	c.Server.HTTPConfig.Auth.TokenBearer.TokenHashes = []string{
		"too-short", // must be 64 hex chars
	}
	if err := c.Validate(); err == nil {
		t.Errorf("Validate() = nil, want error for malformed hash")
	}
}

func TestValidate_HTTPTransport_ValidConfig(t *testing.T) {
	c := Default()
	c.Server.Transport = "http"
	c.Server.HTTPConfig.Addr = "127.0.0.1:8080"
	c.Server.HTTPConfig.Auth.TokenBearer.Enabled = true
	c.Server.HTTPConfig.Auth.TokenBearer.TokenHashes = []string{
		strings.Repeat("a", 64),
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	if c.Server.HTTPConfig.SessionTTL <= 0 {
		t.Errorf("SessionTTL should pick a default")
	}
	if c.Server.HTTPConfig.IdleTimeout <= 0 {
		t.Errorf("IdleTimeout should pick a default")
	}
}

func TestValidate_HTTPTransport_HeaderDefaulted(t *testing.T) {
	c := Default()
	c.Server.Transport = "http"
	c.Server.HTTPConfig.Auth.TokenBearer.Enabled = true
	c.Server.HTTPConfig.Auth.TokenBearer.TokenHashes = []string{
		strings.Repeat("a", 64),
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	if got := c.Server.HTTPConfig.Auth.TokenBearer.HeaderName; got != "Authorization" {
		t.Errorf("HeaderName = %q, want default Authorization", got)
	}
}

// --- ICMP probe validation ---

func TestDefault_ICMPKnobsPopulated(t *testing.T) {
	c := Default()
	if !c.Probes.ICMP.Enabled {
		t.Errorf("ICMP should be enabled by default")
	}
	if c.Probes.ICMP.MaxCount <= 0 {
		t.Errorf("MaxCount should be set by default, got %d", c.Probes.ICMP.MaxCount)
	}
	if c.Probes.ICMP.Interval <= 0 {
		t.Errorf("Interval should be set by default, got %s", c.Probes.ICMP.Interval)
	}
	if c.Probes.ICMP.PayloadSize < 0 {
		t.Errorf("PayloadSize should be >= 0 by default, got %d", c.Probes.ICMP.PayloadSize)
	}
}

func TestValidate_ICMP_FillsMissingDefaults(t *testing.T) {
	c := Default()
	// Wipe the ICMP knobs to simulate a minimal config that does
	// not mention the section.
	c.Probes.ICMP = ICMPProbeConfig{}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	if c.Probes.ICMP.MaxCount != 3 {
		t.Errorf("MaxCount default = %d, want 3", c.Probes.ICMP.MaxCount)
	}
	if c.Probes.ICMP.Interval != 1*time.Second {
		t.Errorf("Interval default = %s, want 1s", c.Probes.ICMP.Interval)
	}
	if c.Probes.ICMP.PayloadSize != 0 {
		t.Errorf("PayloadSize default = %d, want 0", c.Probes.ICMP.PayloadSize)
	}
}

func TestValidate_ICMP_RejectsOverCeilings(t *testing.T) {
	c := Default()
	c.Probes.ICMP.MaxCount = 11
	if err := c.Validate(); err == nil {
		t.Errorf("expected error when MaxCount > 10")
	}
}

func TestValidate_ICMP_RejectsUnderFloor(t *testing.T) {
	c := Default()
	c.Probes.ICMP.Interval = 100 * time.Millisecond
	if err := c.Validate(); err == nil {
		t.Errorf("expected error when Interval < 200ms")
	}
}

func TestValidate_ICMP_RejectsPayloadOutOfRange(t *testing.T) {
	for _, sz := range []int{-1, 1401} {
		c := Default()
		c.Probes.ICMP.PayloadSize = sz
		if err := c.Validate(); err == nil {
			t.Errorf("expected error when PayloadSize = %d", sz)
		}
	}
}
