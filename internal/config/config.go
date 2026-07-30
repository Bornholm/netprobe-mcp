package config

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Security SecurityConfig `yaml:"security"`
	Limits   LimitsConfig   `yaml:"limits"`
	Probes   ProbesConfig   `yaml:"probes"`
	Audit    AuditConfig    `yaml:"audit"`
	Metrics  MetricsConfig  `yaml:"metrics"`
}

type ServerConfig struct {
	Transport     string        `yaml:"transport"`
	Name          string        `yaml:"name"`
	Version       string        `yaml:"version"`
	Instructions  string        `yaml:"instructions"`
	ShutdownGrace time.Duration `yaml:"shutdown_grace"`
}

type SecurityConfig struct {
	Targets TargetPolicy  `yaml:"targets"`
	Network NetworkPolicy `yaml:"network"`
	DNS     DNSPolicy     `yaml:"dns"`
}

type TargetPolicy struct {
	Allow []TargetRule `yaml:"allow"`
	Deny  []TargetRule `yaml:"deny"`
}

type TargetRule struct {
	Type    string      `yaml:"type"`
	Pattern string      `yaml:"pattern"`
	Ports   []PortRange `yaml:"ports"`
	Schemes []string    `yaml:"schemes"`
	Tools   []string    `yaml:"tools"`
	// Purposes restrict the rule to a closed set of
	// security.Purpose values. Empty means "any purpose". This is
	// how secondary SSRF channels (AIA, OCSP direct) are gated:
	// the regular TargetRule for the probe is annotated with
	// ["probe"] and a separate rule carries ["aia_fetch"] so the
	// operator must opt in twice.
	Purposes []string `yaml:"purposes"`
	Comment  string   `yaml:"comment"`
}

type PortRange struct {
	From uint16 `yaml:"from"`
	To   uint16 `yaml:"to"`
}

type NetworkPolicy struct {
	DenyCIDRs        []string `yaml:"deny_cidrs"`
	AllowCIDRs       []string `yaml:"allow_cidrs"`
	BlockPrivate     *bool    `yaml:"block_private"`
	BlockLoopback    *bool    `yaml:"block_loopback"`
	BlockLinkLocal   *bool    `yaml:"block_link_local"`
	BlockMulticast   *bool    `yaml:"block_multicast"`
	BlockUnspecified *bool    `yaml:"block_unspecified"`
	BlockCloudMeta   *bool    `yaml:"block_cloud_metadata"`
	AllowIPv4        *bool    `yaml:"allow_ipv4"`
	AllowIPv6        *bool    `yaml:"allow_ipv6"`
	SourceIP         string   `yaml:"source_ip"`
	// DisableDefaultBogons removes the hardcoded list of RFC1918 / loopback
	// / etc. prefixes. ONLY intended for integration tests; production use
	// should never disable this.
	DisableDefaultBogons bool `yaml:"disable_default_bogons"`
}

func (n NetworkPolicy) PrivateBlocked() bool {
	if n.BlockPrivate == nil {
		return true
	}
	return *n.BlockPrivate
}

func (n NetworkPolicy) LoopbackBlocked() bool {
	if n.BlockLoopback == nil {
		return true
	}
	return *n.BlockLoopback
}

func (n NetworkPolicy) LinkLocalBlocked() bool {
	if n.BlockLinkLocal == nil {
		return true
	}
	return *n.BlockLinkLocal
}

func (n NetworkPolicy) MulticastBlocked() bool {
	if n.BlockMulticast == nil {
		return true
	}
	return *n.BlockMulticast
}

func (n NetworkPolicy) UnspecifiedBlocked() bool {
	if n.BlockUnspecified == nil {
		return true
	}
	return *n.BlockUnspecified
}

func (n NetworkPolicy) CloudMetaBlocked() bool {
	if n.BlockCloudMeta == nil {
		return true
	}
	return *n.BlockCloudMeta
}

func (n NetworkPolicy) IPv4Allowed() bool {
	if n.AllowIPv4 == nil {
		return true
	}
	return *n.AllowIPv4
}

func (n NetworkPolicy) IPv6Allowed() bool {
	if n.AllowIPv6 == nil {
		return false
	}
	return *n.AllowIPv6
}

type DNSPolicy struct {
	Resolvers           []string      `yaml:"resolvers"`
	Timeout             time.Duration `yaml:"timeout"`
	CacheTTL            time.Duration `yaml:"cache_ttl"`
	CacheMaxEntries     int           `yaml:"cache_max_entries"`
	MaxAddressesPerName int           `yaml:"max_addresses_per_name"`
	// Query controls — anti-exfiltration
	AllowedQueryTypes      []string `yaml:"allowed_query_types"`
	MaxNameLength          int      `yaml:"max_name_length"`
	MaxLabels              int      `yaml:"max_labels"`
	MaxLabelLength         int      `yaml:"max_label_length"`
	BlockHighEntropyLabels bool     `yaml:"block_high_entropy_labels"`
	MaxEntropyBits         float64  `yaml:"max_entropy_bits"`
}

type LimitsConfig struct {
	Global              RateLimit            `yaml:"global"`
	PerTool             map[string]RateLimit `yaml:"per_tool"`
	PerTarget           RateLimit            `yaml:"per_target"`
	PerSession          RateLimit            `yaml:"per_session"`
	MaxConcurrentProbes int                  `yaml:"max_concurrent_probes"`
	KeyedLimiterTTL     time.Duration        `yaml:"keyed_limiter_ttl"`
	KeyedLimiterMaxKeys int                  `yaml:"keyed_limiter_max_keys"`
	MaxCallsPerSession  int                  `yaml:"max_calls_per_session"`
}

type RateLimit struct {
	RPS   float64 `yaml:"rps"`
	Burst int     `yaml:"burst"`
}

type ProbesConfig struct {
	DefaultTimeout time.Duration   `yaml:"default_timeout"`
	MaxTimeout     time.Duration   `yaml:"max_timeout"`
	TCP            TCPProbeConfig  `yaml:"tcp"`
	HTTP           HTTPProbeConfig `yaml:"http"`
	DNS            DNSProbeConfig  `yaml:"dns"`
	TLS            TLSDiagConfig   `yaml:"tls"`
}

type TCPProbeConfig struct {
	Enabled      bool  `yaml:"enabled"`
	MaxReadBytes int64 `yaml:"max_read_bytes"`
}

// HTTPProbeConfig governs the http_probe tool.
type HTTPProbeConfig struct {
	Enabled          bool     `yaml:"enabled"`
	MaxBodyBytes     int64    `yaml:"max_body_bytes"`
	MaxReturnedBytes int64    `yaml:"max_returned_bytes"`
	HeaderAllowList  []string `yaml:"header_allow_list"`
	AllowRedirect    *bool    `yaml:"allow_redirect"`
	MaxRedirects     int      `yaml:"max_redirects"`
}

// TLSDiagConfig governs the tls_diagnose tool. The v1 implementation is
// strictly passive: one handshake, one chain inspection, one passive OCSP
// read. AIA fetching and direct OCSP queries (both secondary SSRF
// channels controlled by a remote certificate) are intentionally hard-off
// here so that misconfiguration cannot enable them by accident.
type TLSDiagConfig struct {
	Enabled bool `yaml:"enabled"`

	// Default port used when the tool call does not specify one.
	DefaultPort uint16 `yaml:"default_port"`

	// Global time budget for a single Diagnose call. v1 is one handshake,
	// so the budget is intentionally generous; future active phases will
	// share it.
	TotalBudget time.Duration `yaml:"total_budget"`

	// Handshake timeout.
	HandshakeTimeout time.Duration `yaml:"handshake_timeout"`

	// MinTLSVersion defaults to TLS 1.2 (TLS 1.0/1.1 are deprecated and
	// kept probe-able only via active phases, off by default in v1).
	// Allowed values: "1.2", "1.3".
	MinTLSVersion string `yaml:"min_tls_version"`

	// MaxTLSVersion defaults to TLS 1.3. Allowed: "1.2", "1.3".
	MaxTLSVersion string `yaml:"max_tls_version"`

	// AllowAIAFetch is the operator opt-in for AIA chasing. Off by
	// default. When true, individual AIA fetches are still gated by
	// the Guard with Purpose=aia_fetch; the operator MUST declare
	// the corresponding TargetRule in the allow-list.
	AllowAIAFetch bool `yaml:"allow_aia_fetch"`

	// AllowOCSPQuery is the operator opt-in for direct OCSP
	// queries. Same gating as AllowAIAFetch.
	AllowOCSPQuery bool `yaml:"allow_ocsp_query"`

	// Expiry thresholds.
	ExpiringSoonDays     int `yaml:"expiring_soon_days"`     // default 30
	ExpiringCriticalDays int `yaml:"expiring_critical_days"` // default 7

	// Validity thresholds.
	MaxValidityDays       int `yaml:"max_validity_days"`       // CA/B Forum: 398
	ExcessiveValidityDays int `yaml:"excessive_validity_days"` // browser cutoff: 825

	// Weak crypto thresholds.
	MinRSAKeyBits int `yaml:"min_rsa_key_bits"` // default 2048
	MinECKeyBits  int `yaml:"min_ec_key_bits"`  // default 256

	// RootCAs is an optional PEM bundle used as a trust anchor pool.
	// When empty, the system pool is used. Tests inject a custom pool
	// via Analyzer.SetRootCAs instead.
	RootCAs []string `yaml:"root_cas"`
}

// isKnownTLSVersion validates MinVersion/MaxVersion strings.
func isKnownTLSVersion(v string) bool {
	switch v {
	case "1.2", "1.3":
		return true
	}
	return false
}

// DNSProbeConfig governs the dns_probe tool. It enforces a closed set of
// behaviour to prevent the server from being abused as an open resolver or as
// an exfiltration channel (DNS tunneling).
type DNSProbeConfig struct {
	Enabled bool `yaml:"enabled"`

	// The DNS server(s) the agent may query. Empty means "use the system
	// resolver" only if AllowSystemResolver is true. Allowing arbitrary
	// servers via the LLM is unsafe; we rely on the regular Guard
	// allow-list to keep this honest.
	AllowedServers      []TargetRule `yaml:"allowed_servers"`
	AllowSystemResolver bool         `yaml:"allow_system_resolver"`

	// The QNAME the agent may resolve also passes through the regular
	// Guard allow-list (no separate rule required). When
	// RestrictQueryNames is true the QNAME must additionally satisfy the
	// structural constraints below.
	RestrictQueryNames bool `yaml:"restrict_query_names"`

	// AllowedQueryTypes is the closed set of RR types the probe may send.
	// Defaults to ["A","AAAA"] which covers 95 % of legitimate use cases.
	AllowedQueryTypes []string `yaml:"allowed_query_types"`

	// Transport-level restrictions.
	AllowUDP        bool   `yaml:"allow_udp"`
	AllowTCP        bool   `yaml:"allow_tcp"`
	AllowDoT        bool   `yaml:"allow_dot"`
	DefaultProtocol string `yaml:"default_protocol"` // udp | tcp | tcp-tls

	// Structural anti-exfiltration guards.
	MaxNameLength          int     `yaml:"max_name_length"`
	MaxLabels              int     `yaml:"max_labels"`
	MaxLabelLength         int     `yaml:"max_label_length"`
	BlockHighEntropyLabels bool    `yaml:"block_high_entropy_labels"`
	MaxEntropyBits         float64 `yaml:"max_entropy_bits"`

	// EDNS0 advertised buffer size. Hard-capped at 65536 to limit
	// amplification potential.
	MaxResponseBytes int `yaml:"max_response_bytes"`

	// Per-query timeout (also bounded by Probes.MaxTimeout).
	Timeout time.Duration `yaml:"timeout"`
}

// DefaultHeaderAllowList is the closed set of request-header names http_probe
// will transmit. Authorization is intentionally absent: passing tokens through
// an LLM-controlled tool is an SSRF-authenticated exfiltration channel.
var DefaultHeaderAllowList = []string{
	"Accept",
	"Accept-Language",
	"User-Agent",
	"Cache-Control",
	"If-None-Match",
	"If-Modified-Since",
}

// sanitizeHeaderAllowList lower-cases entries, drops empty strings and
// rejects Authorization unconditionally.
func sanitizeHeaderAllowList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, h := range in {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if h == "authorization" {
			continue
		}
		out = append(out, h)
	}
	if len(out) == 0 {
		return append([]string{}, lower(DefaultHeaderAllowList...)...)
	}
	return out
}

func lower(in ...string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

type AuditConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Format     string `yaml:"format"`
	Output     string `yaml:"output"`
	Level      string `yaml:"level"`
	LogTargets bool   `yaml:"log_targets"`
}

type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	Path    string `yaml:"path"`
}

func (c *Config) Validate() error {
	var errs []error

	if c.Server.Transport == "" {
		c.Server.Transport = "stdio"
	}
	if c.Server.Transport != "stdio" && c.Server.Transport != "http" {
		errs = append(errs, fmt.Errorf("server.transport must be 'stdio' or 'http', got %q", c.Server.Transport))
	}

	if len(c.Security.Targets.Allow) == 0 {
		errs = append(errs, errors.New("security.targets.allow is empty: deny-by-default requires at least one allow rule"))
	}

	if c.Limits.Global.RPS <= 0 {
		errs = append(errs, errors.New("limits.global.rps must be > 0"))
	}
	if c.Limits.MaxConcurrentProbes <= 0 {
		c.Limits.MaxConcurrentProbes = 8
	}
	if c.Limits.KeyedLimiterMaxKeys <= 0 {
		c.Limits.KeyedLimiterMaxKeys = 2048
	}
	if c.Limits.KeyedLimiterTTL <= 0 {
		c.Limits.KeyedLimiterTTL = 10 * time.Minute
	}
	if c.Limits.MaxCallsPerSession <= 0 {
		c.Limits.MaxCallsPerSession = 500
	}

	if c.Probes.DefaultTimeout <= 0 {
		c.Probes.DefaultTimeout = 10 * time.Second
	}
	if c.Probes.MaxTimeout <= 0 {
		c.Probes.MaxTimeout = 30 * time.Second
	}
	if c.Probes.MaxTimeout > 60*time.Second {
		errs = append(errs, errors.New("probes.max_timeout cannot exceed 60s"))
	}

	if c.Probes.TCP.MaxReadBytes <= 0 {
		c.Probes.TCP.MaxReadBytes = 4096
	}

	if !c.Probes.HTTP.Enabled {
		// leave defaults even if disabled; they will not be read.
	} else {
		if c.Probes.HTTP.MaxBodyBytes <= 0 {
			c.Probes.HTTP.MaxBodyBytes = 1 << 20 // 1 MiB
		}
		if c.Probes.HTTP.MaxBodyBytes > (1 << 26) {
			errs = append(errs, errors.New("probes.http.max_body_bytes cannot exceed 64 MiB"))
		}
		if c.Probes.HTTP.MaxReturnedBytes <= 0 {
			c.Probes.HTTP.MaxReturnedBytes = 4096
		}
		if c.Probes.HTTP.MaxReturnedBytes > c.Probes.HTTP.MaxBodyBytes {
			c.Probes.HTTP.MaxReturnedBytes = c.Probes.HTTP.MaxBodyBytes
		}
		if c.Probes.HTTP.AllowRedirect == nil {
			b := true
			c.Probes.HTTP.AllowRedirect = &b
		}
		if c.Probes.HTTP.MaxRedirects <= 0 {
			c.Probes.HTTP.MaxRedirects = 5
		}
		if c.Probes.HTTP.MaxRedirects > 20 {
			errs = append(errs, errors.New("probes.http.max_redirects cannot exceed 20"))
		}
		c.Probes.HTTP.HeaderAllowList = sanitizeHeaderAllowList(c.Probes.HTTP.HeaderAllowList)
	}

	if c.Security.DNS.Timeout <= 0 {
		c.Security.DNS.Timeout = 3 * time.Second
	}
	if c.Security.DNS.CacheTTL <= 0 {
		c.Security.DNS.CacheTTL = 60 * time.Second
	}
	if c.Security.DNS.CacheMaxEntries <= 0 {
		c.Security.DNS.CacheMaxEntries = 4096
	}
	if c.Security.DNS.MaxAddressesPerName <= 0 {
		c.Security.DNS.MaxAddressesPerName = 4
	}
	// Anti-exfiltration defaults — applied even when the DNS probe itself
	// is disabled so SafeResolver hygiene stays consistent.
	if c.Security.DNS.MaxNameLength <= 0 {
		c.Security.DNS.MaxNameLength = 253
	}
	if c.Security.DNS.MaxLabels <= 0 {
		c.Security.DNS.MaxLabels = 10
	}
	if c.Security.DNS.MaxLabelLength <= 0 {
		c.Security.DNS.MaxLabelLength = 63
	}
	if c.Security.DNS.MaxEntropyBits <= 0 {
		c.Security.DNS.MaxEntropyBits = 4.0
	}

	if c.Probes.DNS.Enabled {
		if len(c.Probes.DNS.AllowedServers) == 0 && !c.Probes.DNS.AllowSystemResolver {
			errs = append(errs, errors.New(
				"probes.dns.enabled but neither probes.dns.allowed_servers nor probes.dns.allow_system_resolver are set"))
		}
		for i, r := range c.Probes.DNS.AllowedServers {
			if err := validateRule(r); err != nil {
				errs = append(errs, fmt.Errorf("probes.dns.allowed_servers[%d]: %w", i, err))
			}
		}
		// Default protocols
		if !c.Probes.DNS.AllowUDP && !c.Probes.DNS.AllowTCP && !c.Probes.DNS.AllowDoT {
			c.Probes.DNS.AllowUDP = true
			c.Probes.DNS.AllowTCP = true
		}
		if c.Probes.DNS.DefaultProtocol == "" {
			c.Probes.DNS.DefaultProtocol = "udp"
		}
		switch c.Probes.DNS.DefaultProtocol {
		case "udp", "tcp", "tcp-tls":
		default:
			errs = append(errs, fmt.Errorf("probes.dns.default_protocol must be one of udp|tcp|tcp-tls, got %q", c.Probes.DNS.DefaultProtocol))
		}
		// Default query types: A and AAAA only.
		if len(c.Probes.DNS.AllowedQueryTypes) == 0 {
			c.Probes.DNS.AllowedQueryTypes = []string{"A", "AAAA"}
		}
		for _, qt := range c.Probes.DNS.AllowedQueryTypes {
			if !isKnownQType(qt) {
				errs = append(errs, fmt.Errorf("probes.dns.allowed_query_types: unknown type %q", qt))
			}
		}
		if c.Probes.DNS.MaxResponseBytes <= 0 {
			c.Probes.DNS.MaxResponseBytes = 4096
		}
		if c.Probes.DNS.MaxResponseBytes > 65536 {
			errs = append(errs, errors.New("probes.dns.max_response_bytes cannot exceed 65536"))
		}
		if c.Probes.DNS.Timeout <= 0 {
			c.Probes.DNS.Timeout = 3 * time.Second
		}
		if c.Probes.DNS.Timeout > c.Probes.MaxTimeout {
			c.Probes.DNS.Timeout = c.Probes.MaxTimeout
		}
	}

	if c.Probes.TLS.Enabled {
		if c.Probes.TLS.DefaultPort == 0 {
			c.Probes.TLS.DefaultPort = 443
		}
		if c.Probes.TLS.TotalBudget <= 0 {
			c.Probes.TLS.TotalBudget = 15 * time.Second
		}
		if c.Probes.TLS.TotalBudget > c.Probes.MaxTimeout {
			c.Probes.TLS.TotalBudget = c.Probes.MaxTimeout
		}
		if c.Probes.TLS.HandshakeTimeout <= 0 {
			c.Probes.TLS.HandshakeTimeout = 10 * time.Second
		}
		if c.Probes.TLS.HandshakeTimeout > c.Probes.TLS.TotalBudget {
			c.Probes.TLS.HandshakeTimeout = c.Probes.TLS.TotalBudget
		}
		if c.Probes.TLS.MinTLSVersion == "" {
			c.Probes.TLS.MinTLSVersion = "1.2"
		}
		if !isKnownTLSVersion(c.Probes.TLS.MinTLSVersion) {
			errs = append(errs, fmt.Errorf("probes.tls.min_tls_version must be one of 1.2|1.3, got %q", c.Probes.TLS.MinTLSVersion))
		}
		if c.Probes.TLS.MaxTLSVersion == "" {
			c.Probes.TLS.MaxTLSVersion = "1.3"
		}
		if !isKnownTLSVersion(c.Probes.TLS.MaxTLSVersion) {
			errs = append(errs, fmt.Errorf("probes.tls.max_tls_version must be one of 1.2|1.3, got %q", c.Probes.TLS.MaxTLSVersion))
		}
		// Opt-in secondary SSRF channels. They are still OFF by
		// default; turning them on requires the operator to
		// explicitly set the flag AND declare a TargetRule with
		// purposes: [aia_fetch] (resp. ocsp_query).
		// AIA fetch URLs are http:// per RFC 5280 §4.2.2.1; the
		// analyser will skip any URL whose scheme is not http.
		_ = c.Probes.TLS.AllowAIAFetch
		_ = c.Probes.TLS.AllowOCSPQuery
		if c.Probes.TLS.ExpiringSoonDays <= 0 {
			c.Probes.TLS.ExpiringSoonDays = 30
		}
		if c.Probes.TLS.ExpiringCriticalDays <= 0 {
			c.Probes.TLS.ExpiringCriticalDays = 7
		}
		if c.Probes.TLS.ExpiringCriticalDays >= c.Probes.TLS.ExpiringSoonDays {
			errs = append(errs, fmt.Errorf("probes.tls.expiring_critical_days (%d) must be < expiring_soon_days (%d)",
				c.Probes.TLS.ExpiringCriticalDays, c.Probes.TLS.ExpiringSoonDays))
		}
		if c.Probes.TLS.MaxValidityDays <= 0 {
			c.Probes.TLS.MaxValidityDays = 398
		}
		if c.Probes.TLS.ExcessiveValidityDays <= 0 {
			c.Probes.TLS.ExcessiveValidityDays = 825
		}
		if c.Probes.TLS.MaxValidityDays >= c.Probes.TLS.ExcessiveValidityDays {
			errs = append(errs, fmt.Errorf("probes.tls.max_validity_days (%d) must be < excessive_validity_days (%d)",
				c.Probes.TLS.MaxValidityDays, c.Probes.TLS.ExcessiveValidityDays))
		}
		if c.Probes.TLS.MinRSAKeyBits <= 0 {
			c.Probes.TLS.MinRSAKeyBits = 2048
		}
		if c.Probes.TLS.MinECKeyBits <= 0 {
			c.Probes.TLS.MinECKeyBits = 256
		}
	}

	if c.Metrics.Enabled && c.Metrics.Addr == "" {
		c.Metrics.Addr = "127.0.0.1:9101"
	}
	if c.Metrics.Enabled && c.Metrics.Path == "" {
		c.Metrics.Path = "/metrics"
	}

	for i, r := range c.Security.Targets.Allow {
		if err := validateRule(r); err != nil {
			errs = append(errs, fmt.Errorf("security.targets.allow[%d]: %w", i, err))
		}
	}
	for i, r := range c.Security.Targets.Deny {
		if err := validateRule(r); err != nil {
			errs = append(errs, fmt.Errorf("security.targets.deny[%d]: %w", i, err))
		}
	}

	return errors.Join(errs...)
}

func validateRule(r TargetRule) error {
	switch r.Type {
	case "exact", "suffix", "glob", "regexp", "cidr":
	default:
		return fmt.Errorf("unknown rule type %q (want exact|suffix|glob|regexp|cidr)", r.Type)
	}
	if r.Pattern == "" {
		return errors.New("pattern is required")
	}
	if r.Type == "regexp" && len(r.Pattern) > 512 {
		return errors.New("regexp pattern too long (max 512 chars)")
	}
	for _, p := range r.Purposes {
		switch p {
		case "probe", "meta", "aia_fetch", "ocsp_query", "icmp_probe":
		default:
			return fmt.Errorf("unknown purpose %q (want probe|meta|aia_fetch|ocsp_query|icmp_probe)", p)
		}
	}
	return nil
}

// isKnownQType returns true when name is one of the RR types the DNS probe
// is willing to send. Kept as a closed list to prevent the agent from
// triggering exotic (and amplification-prone) query types.
func isKnownQType(name string) bool {
	switch strings.ToUpper(name) {
	case "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "SRV", "PTR":
		return true
	}
	return false
}
