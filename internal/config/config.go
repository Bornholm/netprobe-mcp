package config

import (
	"errors"
	"fmt"
	"net/netip"
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

	// HTTPConfig is honoured only when Transport == "http". The
	// Auth block is MANDATORY in HTTP mode: a public-facing MCP
	// network-probe is, by construction, an authenticated SSRF
	// proxy. See PLAN §9.8 §13.8.
	HTTPConfig HTTPConfig `yaml:"http"`
}

// HTTPConfig is the runtime configuration of the Streamable HTTP
// transport. The server refuses to start on http transport without
// an Auth block; this is a deny-by-default invariant.
type HTTPConfig struct {
	Addr           string        `yaml:"addr"`
	AllowedOrigins []string      `yaml:"allowed_origins"` // empty = reject all
	SessionTTL     time.Duration `yaml:"session_ttl"`
	ReadTimeout    time.Duration `yaml:"read_timeout"`
	WriteTimeout   time.Duration `yaml:"write_timeout"`
	IdleTimeout    time.Duration `yaml:"idle_timeout"`

	// Auth controls how incoming HTTP requests are authenticated.
	// The zero value is "auth required but none configured": the
	// server refuses to start until at least one auth provider is
	// enabled.
	//
	// TokenBearer requires an Authorization: Bearer <token> header.
	// The tokens are checked against TokenHashes with a
	// constant-time comparison, so plain tokens never live on disk.
	Auth HTTPAuth `yaml:"auth"`
}

// HTTPAuth configures the authentication schemes accepted by the
// HTTP transport. Multiple schemes can be enabled: at least one
// must be enabled, otherwise the server refuses to start.
type HTTPAuth struct {
	TokenBearer TokenBearerAuth `yaml:"token_bearer"`
}

// TokenBearerAuth validates clients with a static set of bearer
// tokens. Tokens are stored as SHA-256 hashes so the YAML file
// itself never leaks plaintext credentials.
//
// On Linux the recommended CLI helper is
// `netprobe-mcp hash <plain>` which prints the SHA-256 hex of the
// token (see cmd/netprobe-mcp). The encoding is the one used by
// internal/auth.HashToken, kept in one place.
type TokenBearerAuth struct {
	// Enabled turns the bearer-token auth scheme on.
	Enabled bool `yaml:"enabled"`
	// TokenHashes is the set of accepted SHA-256 hex tokens.
	// Required when Enabled is true and no other scheme is on.
	TokenHashes []string `yaml:"token_hashes"`
	// HeaderName is the header to look for. Defaults to Authorization.
	HeaderName string `yaml:"header_name"`
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
	ICMP           ICMPProbeConfig `yaml:"icmp"`
	GRPC           GRPCProbeConfig `yaml:"grpc"`
	TLS            TLSDiagConfig   `yaml:"tls"`
}

// GRPCProbeConfig governs the grpc_probe tool.
//
// Per PLAN §7.6, only the gRPC Health Checking Protocol
// (/grpc.health.v1.Health/Check) is exposed. No reflection, no
// arbitrary method invocation. The Service field is a *name*, not
// an instruction: it is passed verbatim into the HealthCheckRequest,
// which the server interprets; the prober never uses it to pick
// an RPC method or target.
type GRPCProbeConfig struct {
	Enabled bool `yaml:"enabled"`

	// DefaultPort used when the call does not specify one. 50051
	// is the standard plaintext gRPC port; 443 is common when
	// gRPC is reverse-proxied behind TLS.
	DefaultPort uint16 `yaml:"default_port"`

	// HandshakeTimeout caps the TLS handshake when UseTLS=true.
	// Set this low: gRPC probes are shallow, they should never
	// wait more than a few seconds.
	HandshakeTimeout time.Duration `yaml:"handshake_timeout"`
}

// TCPProbeConfig governs the tcp_probe tool.
//
// Per PLAN §7.3, only NAMED, hard-coded dialogues are exposed
// (smtp_banner, imap_capability, pop3_banner, mysql_handshake).
// The agent never gets a free-form `send/expect` field. The
// AllowQueryResponse knob exists solely so we can REJECT it at
// boot — letting it slip into the config would silently re-open
// the SSRF-by-protocol channel the PLAN warns about (Redis
// CONFIG SET, Memcached flush, SMTP relaying).
type TCPProbeConfig struct {
	// Enabled toggles tcp_probe registration.
	Enabled bool `yaml:"enabled"`

	// MaxReadBytes caps how many bytes the prober reads from the
	// peer (banner read + dialogue steps). Bounded so a malicious
	// server cannot exhaust memory.
	MaxReadBytes int64 `yaml:"max_read_bytes"`

	// AllowQueryResponse MUST be false. It exists for the sole
	// purpose of being refused at Validate() time. Any other
	// value is a configuration error.
	AllowQueryResponse bool `yaml:"allow_query_response"`
}

// ICMPProbeConfig governs the icmp_probe tool. The thresholds are
// clamped at runtime to keep the floor values mandated by the
// protocol (200ms interval, 1400-byte payload cap, 10 packets) and
// to defend against an LLM requesting arbitrarily long probes
// against a single target. The hard caps below are applied
// independently of the configured values; setting a larger number
// does not raise them.
type ICMPProbeConfig struct {
	// Enabled toggles the probe registration. When false, the
	// tool is not advertised to the MCP client.
	Enabled bool `yaml:"enabled"`

	// MaxCount is the upper bound on echo requests per call.
	// Hard-capped at 10 in the prober (PLAN §7.4).
	MaxCount int `yaml:"max_count"`

	// Interval is the delay between echo requests. Hard-capped
	// at 200ms minimum in the prober.
	Interval time.Duration `yaml:"interval"`

	// PayloadSize is the per-echo payload in bytes (after the
	// 16-byte magic prefix). Hard-capped at 1400 bytes; values
	// outside [0,1400] are rejected at validate time.
	PayloadSize int `yaml:"payload_size"`
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

// Default returns the built-in policy used when no --config flag is
// supplied. It is "safe and non-invasive" rather than "open": it lets
// the agent exercise every tool against a small, curated set of public
// diagnostic endpoints and the loopback range, while keeping private
// networks, link-local, multicast, and the cloud-metadata IP blocked.
//
// This default is intended for local evaluation, demos, and CI
// smoke-tests against real public services. For production use, ship
// your own policy file with explicit allow-rules for the targets you
// actually probe.
func Default() *Config {
	c := &Config{}

	c.Server.Transport = "stdio"
	c.Server.Name = "netprobe-mcp"
	c.Server.Version = "0.1.0"
	c.Server.ShutdownGrace = 10 * time.Second

	// Allow rules. The set is small on purpose: a handful of public
	// hosts that are designed to be probed (RFC 2606 examples, the
	// Cloudflare and Google public resolvers), plus loopback for
	// local listeners.
	c.Security.Targets.Allow = []TargetRule{
		{
			Type:    "suffix",
			Pattern: "example.com",
			Tools:   []string{"tcp_probe", "http_probe", "dns_probe", "tls_diagnose", "icmp_probe"},
			Comment: "RFC 2606 reserved example domain",
		},
		{
			Type:    "suffix",
			Pattern: "example.org",
			Tools:   []string{"tcp_probe", "http_probe", "dns_probe", "tls_diagnose", "icmp_probe"},
			Comment: "RFC 2606 reserved example domain",
		},
		{
			Type:    "suffix",
			Pattern: "example.net",
			Tools:   []string{"tcp_probe", "http_probe", "dns_probe", "tls_diagnose", "icmp_probe"},
			Comment: "RFC 2606 reserved example domain",
		},
		{
			Type:    "exact",
			Pattern: "dns.google",
			Tools:   []string{"dns_probe", "tcp_probe", "tls_diagnose"},
			Comment: "Google Public DNS (read-only diagnostic endpoint)",
		},
		{
			Type:    "exact",
			Pattern: "one.one.one.one",
			Tools:   []string{"dns_probe", "tcp_probe", "tls_diagnose"},
			Comment: "Cloudflare 1.1.1.1 resolver hostname",
		},
		{
			Type:    "exact",
			Pattern: "cloudflare.com",
			Tools:   []string{"http_probe", "tls_diagnose"},
			Comment: "Cloudflare root (TLS chain test)",
		},
		{
			Type:    "cidr",
			Pattern: "127.0.0.0/8",
			Tools:   []string{"tcp_probe", "http_probe", "dns_probe", "tls_diagnose", "icmp_probe", "probe_check_target"},
			Comment: "loopback for local testing",
		},
	}

	// Network block-list. Private, loopback, link-local, multicast,
	// unspecified, and cloud-metadata are all denied by default.
	// bogons stays on (this is not a test).
	c.Security.Network.DisableDefaultBogons = false

	// DNS policy: no system resolver (forces use of allow-listed
	// servers), no DoT (avoids a secondary dial path), short timeout,
	// strict anti-exfiltration caps.
	c.Security.DNS.Timeout = 3 * time.Second
	c.Security.DNS.CacheTTL = 60 * time.Second
	c.Security.DNS.CacheMaxEntries = 4096
	c.Security.DNS.MaxAddressesPerName = 4
	c.Security.DNS.MaxNameLength = 253
	c.Security.DNS.MaxLabels = 10
	c.Security.DNS.MaxLabelLength = 63
	c.Security.DNS.BlockHighEntropyLabels = true
	c.Security.DNS.MaxEntropyBits = 4.0

	// Rate limits. Tight enough that one runaway session cannot
	// abuse the server, loose enough that legitimate interactive use
	// is not throttled.
	c.Limits.Global = RateLimit{RPS: 5, Burst: 10}
	c.Limits.PerTarget = RateLimit{RPS: 0.5, Burst: 3}
	c.Limits.PerSession = RateLimit{RPS: 2, Burst: 5}
	c.Limits.PerTool = map[string]RateLimit{
		"tcp_probe":    {RPS: 3, Burst: 6},
		"http_probe":   {RPS: 2, Burst: 4},
		"dns_probe":    {RPS: 2, Burst: 4},
		"tls_diagnose": {RPS: 2, Burst: 4},
	}
	c.Limits.MaxConcurrentProbes = 8
	c.Limits.KeyedLimiterTTL = 10 * time.Minute
	c.Limits.KeyedLimiterMaxKeys = 2048
	c.Limits.MaxCallsPerSession = 500

	// Probes.
	c.Probes.DefaultTimeout = 10 * time.Second
	c.Probes.MaxTimeout = 30 * time.Second

	c.Probes.TCP.Enabled = true
	c.Probes.TCP.MaxReadBytes = 4096

	c.Probes.HTTP.Enabled = true
	c.Probes.HTTP.MaxBodyBytes = 1 << 20 // 1 MiB
	c.Probes.HTTP.MaxReturnedBytes = 4096
	c.Probes.HTTP.HeaderAllowList = append([]string{}, DefaultHeaderAllowList...)
	allow := true
	c.Probes.HTTP.AllowRedirect = &allow
	c.Probes.HTTP.MaxRedirects = 5

	c.Probes.DNS.Enabled = true
	c.Probes.DNS.AllowSystemResolver = false
	c.Probes.DNS.RestrictQueryNames = true
	c.Probes.DNS.AllowedQueryTypes = []string{"A", "AAAA"}
	c.Probes.DNS.AllowUDP = true
	c.Probes.DNS.AllowTCP = true
	c.Probes.DNS.AllowDoT = false
	c.Probes.DNS.DefaultProtocol = "udp"
	c.Probes.DNS.MaxResponseBytes = 4096
	c.Probes.DNS.Timeout = 3 * time.Second
	// Loopback DNS for local testing. The prober will hit this when
	// running against 127.0.0.0/8 targets.
	c.Probes.DNS.AllowedServers = []TargetRule{
		{
			Type:    "cidr",
			Pattern: "127.0.0.0/8",
			Tools:   []string{"dns_probe"},
			Comment: "loopback DNS for local testing",
		},
	}

	// ICMP defaults: 3 echoes, 1s apart, 56-byte payload (matches
	// the Linux ping default). The prober may override these via
	// per-call options; the values here are ceilings and floors,
	// not target values.
	c.Probes.ICMP.Enabled = true
	c.Probes.ICMP.MaxCount = 3
	c.Probes.ICMP.Interval = 1 * time.Second
	c.Probes.ICMP.PayloadSize = 56

	c.Probes.GRPC.Enabled = false // off by default; requires operator opt-in
	c.Probes.GRPC.DefaultPort = 50051
	c.Probes.GRPC.HandshakeTimeout = 5 * time.Second

	c.Probes.TLS.Enabled = true
	c.Probes.TLS.DefaultPort = 443
	c.Probes.TLS.TotalBudget = 15 * time.Second
	c.Probes.TLS.HandshakeTimeout = 10 * time.Second
	c.Probes.TLS.MinTLSVersion = "1.2"
	c.Probes.TLS.MaxTLSVersion = "1.3"
	c.Probes.TLS.AllowAIAFetch = false
	c.Probes.TLS.AllowOCSPQuery = false
	c.Probes.TLS.ExpiringSoonDays = 30
	c.Probes.TLS.ExpiringCriticalDays = 7
	c.Probes.TLS.MaxValidityDays = 398
	c.Probes.TLS.ExcessiveValidityDays = 825
	c.Probes.TLS.MinRSAKeyBits = 2048
	c.Probes.TLS.MinECKeyBits = 256

	// Audit: on by default, JSON to stderr (matches the stdio
	// convention of keeping the JSON-RPC stream clean on stdout).
	c.Audit.Enabled = true
	c.Audit.Format = "json"
	c.Audit.Output = "stderr"
	c.Audit.Level = "info"
	c.Audit.LogTargets = false

	// Metrics: on, bound to loopback. Operators who do not want the
	// metrics endpoint can disable it explicitly via --config.
	c.Metrics.Enabled = true
	c.Metrics.Addr = "127.0.0.1:9101"
	c.Metrics.Path = "/metrics"

	if err := c.Validate(); err != nil {
		// Default() must always produce a valid config. A bug here
		// is a programming error, not a user error.
		panic(fmt.Sprintf("config.Default: built-in policy is invalid: %v", err))
	}
	return c
}

// FlagAllowRuleTools is the set of tool names the CLI-derived
// allow-rules apply to. It matches the default loopback rule so
// that --allow-cidr and --allow-hostname feel consistent with the
// built-in policy.
var FlagAllowRuleTools = []string{
	"tcp_probe",
	"http_probe",
	"dns_probe",
	"tls_diagnose",
	"icmp_probe",
	"probe_check_target",
}

// ApplyFlagAllowRules extends cfg with rules built from CLI flag
// values. Each entry in hostnames or cidrs becomes one
// TargetRule appended to Security.Targets.Allow.
//
// Hostname rules: a leading '.' makes the rule a suffix rule
// (".example.com" matches "foo.example.com"). Otherwise the rule is
// an exact match against the normalised hostname.
//
// CIDR rules: parsed with netip.ParsePrefix. Both IPv4 and IPv6
// are accepted; the IPv6 allow-toggle in the network policy still
// applies.
//
// Returns the number of rules appended. Duplicate patterns are
// not deduped; the compiled matcher handles overlap and the first
// match wins, so order is irrelevant.
func ApplyFlagAllowRules(cfg *Config, hostnames, cidrs []string) (int, error) {
	added := 0
	for _, h := range hostnames {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		var rule TargetRule
		if strings.HasPrefix(h, ".") {
			suffix := strings.TrimPrefix(h, ".")
			if suffix == "" {
				return 0, fmt.Errorf("--allow-hostname: empty suffix after leading dot")
			}
			if !strings.Contains(suffix, ".") {
				return 0, fmt.Errorf("--allow-hostname %q: suffix must contain a dot", h)
			}
			rule = TargetRule{
				Type:    "suffix",
				Pattern: suffix,
				Tools:   append([]string{}, FlagAllowRuleTools...),
				Comment: "added via --allow-hostname",
			}
		} else {
			rule = TargetRule{
				Type:    "exact",
				Pattern: h,
				Tools:   append([]string{}, FlagAllowRuleTools...),
				Comment: "added via --allow-hostname",
			}
		}
		cfg.Security.Targets.Allow = append(cfg.Security.Targets.Allow, rule)
		added++
	}

	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return 0, fmt.Errorf("--allow-cidr %q: %w", cidr, err)
		}
		rule := TargetRule{
			Type:    "cidr",
			Pattern: cidr,
			Tools:   append([]string{}, FlagAllowRuleTools...),
			Comment: "added via --allow-cidr",
		}
		cfg.Security.Targets.Allow = append(cfg.Security.Targets.Allow, rule)
		added++
	}

	return added, nil
}

// Validate enforces structural and semantic invariants on the policy.
// When a field is missing or zero, Validate fills in a sensible
// default. This means a partial YAML file is acceptable as long as
// the deny-by-default rules below still hold.
func (c *Config) Validate() error {
	var errs []error

	if c.Server.Transport == "" {
		c.Server.Transport = "stdio"
	}
	if c.Server.Transport != "stdio" && c.Server.Transport != "http" {
		errs = append(errs, fmt.Errorf("server.transport must be 'stdio' or 'http', got %q", c.Server.Transport))
	}

	// HTTP-mode specific validation. The transport is conditionally
	// feature-gated and only the deny-by-default invariants below are
	// enforced here; the rest of the wiring lives in cmd/.
	if c.Server.Transport == "http" {
		if c.Server.HTTPConfig.Addr == "" {
			c.Server.HTTPConfig.Addr = "127.0.0.1:8080"
		}
		if c.Server.HTTPConfig.SessionTTL <= 0 {
			c.Server.HTTPConfig.SessionTTL = 5 * time.Minute
		}
		if c.Server.HTTPConfig.ReadTimeout <= 0 {
			c.Server.HTTPConfig.ReadTimeout = 10 * time.Second
		}
		if c.Server.HTTPConfig.WriteTimeout <= 0 {
			c.Server.HTTPConfig.WriteTimeout = 30 * time.Second
		}
		if c.Server.HTTPConfig.IdleTimeout <= 0 {
			c.Server.HTTPConfig.IdleTimeout = 2 * time.Minute
		}

		// Refuse non-loopback bind without explicit auth opt-in.
		// The model is: loopback can be used for local clients
		// (still requires a token), non-loopback is also token-
		// required; we do NOT loosen auth for any bind.
		if !c.Server.HTTPConfig.Auth.TokenBearer.Enabled || len(c.Server.HTTPConfig.Auth.TokenBearer.TokenHashes) == 0 {
			errs = append(errs, errors.New(
				"server.transport=http requires server.http.auth.token_bearer.enabled with at least one token_hashes entry — "+
					"an unauthenticated HTTP probe server is, by construction, an SSRF proxy open to the network"))
		}
		if c.Server.HTTPConfig.Auth.TokenBearer.HeaderName == "" {
			c.Server.HTTPConfig.Auth.TokenBearer.HeaderName = "Authorization"
		}
		for _, h := range c.Server.HTTPConfig.Auth.TokenBearer.TokenHashes {
			if len(h) != 64 {
				errs = append(errs, fmt.Errorf("server.http.auth.token_bearer.token_hashes: %q is not a 64-character SHA-256 hex digest", h))
			}
		}
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
	// Refuse tcp.allow_query_response=true outright. Per PLAN §7.3,
	// the only safe shape for tcp_probe is the hard-coded dialogue
	// set exposed by the prober; free-form send/expect would let an
	// agent speak any text protocol (Redis CONFIG SET, SMTP relay,
	// MySQL queries, ...). The field exists solely so this check
	// has something to look at.
	if c.Probes.TCP.AllowQueryResponse {
		errs = append(errs, errors.New(
			"probes.tcp.allow_query_response=true is not supported: tcp_probe only exposes hard-coded named dialogues, never free-form query/response"))
	}

	// ICMP defaults. The hard caps in the prober (10 packets,
	// 200ms interval floor, 1400-byte payload cap) remain in
	// force regardless of the configured values; the validation
	// here only fills missing entries with sane defaults.
	if c.Probes.ICMP.MaxCount <= 0 {
		c.Probes.ICMP.MaxCount = 3
	}
	if c.Probes.ICMP.MaxCount > 10 {
		errs = append(errs, fmt.Errorf("probes.icmp.max_count cannot exceed 10 (got %d)", c.Probes.ICMP.MaxCount))
	}
	if c.Probes.ICMP.Interval <= 0 {
		c.Probes.ICMP.Interval = 1 * time.Second
	}
	if c.Probes.ICMP.Interval < 200*time.Millisecond {
		errs = append(errs, fmt.Errorf("probes.icmp.interval cannot be below 200ms (got %s)", c.Probes.ICMP.Interval))
	}
	if c.Probes.ICMP.PayloadSize < 0 || c.Probes.ICMP.PayloadSize > 1400 {
		errs = append(errs, fmt.Errorf("probes.icmp.payload_size must be in 0..1400 (got %d)", c.Probes.ICMP.PayloadSize))
	}

	if c.Probes.GRPC.Enabled {
		if c.Probes.GRPC.DefaultPort == 0 {
			c.Probes.GRPC.DefaultPort = 50051
		}
		if c.Probes.GRPC.HandshakeTimeout <= 0 {
			c.Probes.GRPC.HandshakeTimeout = 5 * time.Second
		}
		if c.Probes.GRPC.HandshakeTimeout > c.Probes.MaxTimeout {
			c.Probes.GRPC.HandshakeTimeout = c.Probes.MaxTimeout
		}
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
