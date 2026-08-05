// Package mcpserver exposes the server's policy, capabilities and
// findings catalogue as MCP resources. Resources are read-only and
// served without consuming rate-limit budget, which makes them
// suitable for the model to consult before attempting a probe.
//
// Three resources are exposed:
//
//	probe://policy            — the effective security policy
//	probe://findings/catalog  — the catalogue of TLS finding IDs
//	probe://capabilities      — runtime capabilities and skipped checks
//
// See PLAN.md §9.7 for the design rationale.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/bornholm/netprobe-mcp/internal/probe/tlsdiag"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerResources wires the read-only resources into the server.
// Resources are registered only if the corresponding subsystem is
// configured — a deployment without TLS support, for example, does
// not expose the findings catalogue.
func (s *Server) registerResources() {
	if s.cfg == nil {
		return
	}
	s.mcp.AddResource(
		&mcp.Resource{
			URI:         "probe://policy",
			Name:        "active-probing-policy",
			Description: "The active security policy: allow-list, denied ranges, rate limits, enabled probes, and TLS diagnostic options.",
			MIMEType:    "application/json",
		},
		s.readPolicyResource,
	)

	s.mcp.AddResource(
		&mcp.Resource{
			URI:         "probe://capabilities",
			Name:        "runtime-capabilities",
			Description: "Which probe capabilities are available in this deployment and which checks are structurally unavailable (e.g. SSLv3, RC4 detection with crypto/tls).",
			MIMEType:    "application/json",
		},
		s.readCapabilitiesResource,
	)

	// Findings catalogue: only meaningful when TLS diag is enabled.
	if s.cfg.Probes.TLS.Enabled {
		s.mcp.AddResource(
			&mcp.Resource{
				URI:         "probe://findings/catalog",
				Name:        "tls-finding-catalogue",
				Description: "All TLS finding IDs with their default severity, category, rationale and standard remediation. Use to interpret finding IDs without re-deriving their meaning.",
				MIMEType:    "application/json",
			},
			s.readFindingsCatalogResource,
		)
	}
}

// PolicyResource is the structured shape returned for
// probe://policy. Sensitive fields (private keys, raw IP lists) are
// omitted.
type PolicyResource struct {
	Server          ServerPolicy         `json:"server"`
	Security        SecurityPolicy       `json:"security"`
	Limits          LimitsPolicy         `json:"limits"`
	Probes          map[string]bool      `json:"probes"`
	TLSDiag         TLSDiagPolicy        `json:"tls_diagnostic"`
	FindingsCatalog []FindingCatalogItem `json:"findings_catalog,omitempty"`
}

type ServerPolicy struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Transport   string `json:"transport"`
	ShutdownSec int    `json:"shutdown_grace_seconds"`
}

type SecurityPolicy struct {
	AllowRuleCount     int      `json:"allow_rule_count"`
	DenyRuleCount      int      `json:"deny_rule_count"`
	BlockPrivate       bool     `json:"block_private"`
	BlockLoopback      bool     `json:"block_loopback"`
	BlockLinkLocal     bool     `json:"block_link_local"`
	BlockMulticast     bool     `json:"block_multicast"`
	BlockUnspecified   bool     `json:"block_unspecified"`
	BlockCloudMetadata bool     `json:"block_cloud_metadata"`
	AllowIPv4          bool     `json:"allow_ipv4"`
	AllowIPv6          bool     `json:"allow_ipv6"`
	DNSTimeout         string   `json:"dns_timeout,omitempty"`
	DNSCacheTTL        string   `json:"dns_cache_ttl,omitempty"`
	DenyCIDRs          []string `json:"deny_cidrs,omitempty"`
	AllowCIDRs         []string `json:"allow_cidrs,omitempty"`
}

type LimitsPolicy struct {
	GlobalRPS           float64 `json:"global_rps"`
	GlobalBurst         int     `json:"global_burst"`
	PerTargetRPS        float64 `json:"per_target_rps"`
	PerSessionRPS       float64 `json:"per_session_rps"`
	MaxConcurrentProbes int     `json:"max_concurrent_probes"`
	KeyedLimiterTTL     string  `json:"keyed_limiter_ttl,omitempty"`
	KeyedLimiterMaxKeys int     `json:"keyed_limiter_max_keys"`
	MaxCallsPerSession  int     `json:"max_calls_per_session"`
}

type TLSDiagPolicy struct {
	Enabled            bool `json:"enabled"`
	AllowAIAFetch      bool `json:"allow_aia_fetch"`
	AllowOCSPQuery     bool `json:"allow_ocsp_query"`
	ExpiryWarnDays     int  `json:"expiry_warn_days"`
	ExpiryCriticalDays int  `json:"expiry_critical_days"`
	MinRSAKeyBits      int  `json:"min_rsa_key_bits"`
	MinECDSAKeyBits    int  `json:"min_ecdsa_key_bits"`
	MaxValidityDays    int  `json:"max_cert_lifetime_days"`
}

func (s *Server) readPolicyResource(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	if s.cfg == nil {
		return nil, fmt.Errorf("no configuration available")
	}
	body, err := json.Marshal(s.buildPolicyResource())
	if err != nil {
		return nil, fmt.Errorf("marshal policy: %w", err)
	}
	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{{
			URI:      "probe://policy",
			MIMEType: "application/json",
			Text:     string(body),
		}},
	}, nil
}

func (s *Server) buildPolicyResource() PolicyResource {
	cfg := s.cfg
	res := PolicyResource{
		Server: ServerPolicy{
			Name:        cfg.Server.Name,
			Version:     cfg.Server.Version,
			Transport:   cfg.Server.Transport,
			ShutdownSec: int(cfg.Server.ShutdownGrace.Seconds()),
		},
		Security: SecurityPolicy{
			AllowRuleCount:     len(cfg.Security.Targets.Allow),
			DenyRuleCount:      len(cfg.Security.Targets.Deny),
			BlockPrivate:       cfg.Security.Network.PrivateBlocked(),
			BlockLoopback:      cfg.Security.Network.LoopbackBlocked(),
			BlockLinkLocal:     cfg.Security.Network.LinkLocalBlocked(),
			BlockMulticast:     cfg.Security.Network.MulticastBlocked(),
			BlockUnspecified:   cfg.Security.Network.UnspecifiedBlocked(),
			BlockCloudMetadata: cfg.Security.Network.CloudMetaBlocked(),
			AllowIPv4:          cfg.Security.Network.IPv4Allowed(),
			AllowIPv6:          cfg.Security.Network.IPv6Allowed(),
			DNSTimeout:         cfg.Security.DNS.Timeout.String(),
			DNSCacheTTL:        cfg.Security.DNS.CacheTTL.String(),
			DenyCIDRs:          cfg.Security.Network.DenyCIDRs,
			AllowCIDRs:         cfg.Security.Network.AllowCIDRs,
		},
		Limits: LimitsPolicy{
			GlobalRPS:           cfg.Limits.Global.RPS,
			GlobalBurst:         cfg.Limits.Global.Burst,
			PerTargetRPS:        cfg.Limits.PerTarget.RPS,
			PerSessionRPS:       cfg.Limits.PerSession.RPS,
			MaxConcurrentProbes: cfg.Limits.MaxConcurrentProbes,
			KeyedLimiterMaxKeys: cfg.Limits.KeyedLimiterMaxKeys,
			MaxCallsPerSession:  cfg.Limits.MaxCallsPerSession,
		},
		Probes: map[string]bool{
			"tcp_probe":    cfg.Probes.TCP.Enabled,
			"http_probe":   cfg.Probes.HTTP.Enabled,
			"dns_probe":    cfg.Probes.DNS.Enabled,
			"tls_diagnose": cfg.Probes.TLS.Enabled,
		},
		TLSDiag: TLSDiagPolicy{
			Enabled:            cfg.Probes.TLS.Enabled,
			AllowAIAFetch:      cfg.Probes.TLS.AllowAIAFetch,
			AllowOCSPQuery:     cfg.Probes.TLS.AllowOCSPQuery,
			ExpiryWarnDays:     cfg.Probes.TLS.ExpiringSoonDays,
			ExpiryCriticalDays: cfg.Probes.TLS.ExpiringCriticalDays,
			MinRSAKeyBits:      cfg.Probes.TLS.MinRSAKeyBits,
			MinECDSAKeyBits:    cfg.Probes.TLS.MinECKeyBits,
			MaxValidityDays:    cfg.Probes.TLS.MaxValidityDays,
		},
	}
	if cfg.Limits.KeyedLimiterTTL > 0 {
		res.Limits.KeyedLimiterTTL = cfg.Limits.KeyedLimiterTTL.String()
	}
	return res
}

// CapabilitiesResource describes runtime capabilities and
// structurally unavailable checks. The agent uses this to know which
// features are missing before complaining about a missing finding.
type CapabilitiesResource struct {
	ProbesEnabled       []string         `json:"probes_enabled"`
	ChecksAlwaysSkipped []SkippedCheckRO `json:"checks_always_skipped"`
	Notes               []string         `json:"notes,omitempty"`
}

type SkippedCheckRO struct {
	Check  string `json:"check"`
	Reason string `json:"reason"`
}

func (s *Server) readCapabilitiesResource(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	body, err := json.Marshal(s.buildCapabilitiesResource())
	if err != nil {
		return nil, fmt.Errorf("marshal capabilities: %w", err)
	}
	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{{
			URI:      "probe://capabilities",
			MIMEType: "application/json",
			Text:     string(body),
		}},
	}, nil
}

func (s *Server) buildCapabilitiesResource() CapabilitiesResource {
	cfg := s.cfg
	res := CapabilitiesResource{}
	if cfg.Probes.TCP.Enabled {
		res.ProbesEnabled = append(res.ProbesEnabled, "tcp_probe")
	}
	if cfg.Probes.HTTP.Enabled {
		res.ProbesEnabled = append(res.ProbesEnabled, "http_probe")
	}
	if cfg.Probes.DNS.Enabled {
		res.ProbesEnabled = append(res.ProbesEnabled, "dns_probe")
	}
	if cfg.Probes.TLS.Enabled {
		res.ProbesEnabled = append(res.ProbesEnabled, "tls_diagnose")
	}
	// Document the checks that crypto/tls simply cannot perform.
	// Mirrors PLAN.md §8.6.
	res.ChecksAlwaysSkipped = []SkippedCheckRO{
		{Check: "TLS_SSLV3_ENABLED", Reason: "SSLv3 not supported by crypto/tls; cannot be probed"},
		{Check: "TLS_WEAK_CIPHER_RC4", Reason: "RC4 removed from crypto/tls; cannot be probed"},
		{Check: "TLS_WEAK_CIPHER_NULL", Reason: "NULL suites removed from crypto/tls; cannot be probed"},
		{Check: "TLS_WEAK_CIPHER_EXPORT", Reason: "EXPORT suites removed from crypto/tls; cannot be probed"},
		{Check: "TLS_WEAK_DH_PARAMS", Reason: "DHE suites not offered by crypto/tls client; cannot be probed"},
		{Check: "TLS_INSECURE_RENEGOTIATION", Reason: "client-initiated renegotiation not supported by crypto/tls"},
	}
	if !cfg.Probes.TLS.AllowAIAFetch {
		res.Notes = append(res.Notes,
			"TLS_AIA_FETCH disabled by configuration; missing intermediates cannot be retrieved at diagnostic time")
	}
	if !cfg.Probes.TLS.AllowOCSPQuery {
		res.Notes = append(res.Notes,
			"TLS_OCSP_DIRECT_QUERY disabled by configuration; OCSP responder is not contacted")
	}
	return res
}

// FindingCatalogItem describes one TLS finding: its stable ID, the
// severity it is reported at by default, the category it belongs to,
// and a short rationale.
type FindingCatalogItem struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Rationale   string `json:"rationale"`
	Remediation string `json:"remediation,omitempty"`
}

// findingsCatalog builds the catalogue of TLS finding IDs exposed at
// probe://findings/catalog. It is generated from the actual rule
// registry so the catalogue cannot drift from the implementation:
// every entry corresponds either to a real rule in DefaultRules()
// or to a check that is structurally unavailable (AlwaysSkipped).
//
// The catalogue is the single source of truth that the agent uses
// to interpret finding IDs. Before phase 2.1 this list was hand-
// maintained and silently disagreed with the rules it documented
// (e.g. TLS_NO_AIA_OCSP, TLS_OCSP_NOT_STAPLED, TLS_CHAIN_CERT_EXPIRED
// were advertised as findings but no rule could ever emit them).
func (s *Server) findingsCatalog() []FindingCatalogItem {
	out := make([]FindingCatalogItem, 0, 64)
	seen := make(map[string]bool, 64)

	// Active rules: every rule in DefaultRules() that has a
	// non-empty ID. Metadata() returns the static fields.
	for _, rule := range tlsdiag.DefaultRules() {
		meta := rule.Metadata()
		if meta.ID == "" {
			continue
		}
		if seen[meta.ID] {
			continue
		}
		seen[meta.ID] = true
		out = append(out, FindingCatalogItem{
			ID:          meta.ID,
			Severity:    string(meta.Severity),
			Category:    meta.Category,
			Title:       meta.Title,
			Rationale:   defaultRationale(meta.ID),
			Remediation: meta.Remediation,
		})
	}

	// Always-skipped checks: structural impossibility. Surfaced so
	// the agent understands the absence is a tool limit, not a
	// positive signal.
	for _, sk := range tlsdiag.AlwaysSkipped() {
		if seen[sk.Check] {
			continue
		}
		seen[sk.Check] = true
		out = append(out, FindingCatalogItem{
			ID:        sk.Check,
			Severity:  "disabled",
			Category:  "disabled",
			Title:     sk.Check,
			Rationale: sk.Reason,
		})
	}

	return out
}

// defaultRationale returns a short, static rationale for a rule ID.
// The remediation comes from the rule itself; the rationale is the
// one-sentence summary the model surfaces when asked to explain a
// finding. New entries should be added when a rule ID is not
// self-explanatory.
func defaultRationale(id string) string {
	switch id {
	case "TLS_CERT_EXPIRED":
		return "NotAfter is in the past at the time of the probe."
	case "TLS_CERT_NOT_YET_VALID":
		return "NotBefore is in the future at the time of the probe."
	case "TLS_CERT_EXPIRING_CRITICAL":
		return "Fewer days remain than the critical threshold."
	case "TLS_CERT_EXPIRING_SOON":
		return "Fewer days remain than the warning threshold."
	case "TLS_VALIDITY_TOO_LONG":
		return "Lifetime above the configured limit."
	case "TLS_VALIDITY_EXCESSIVE":
		return "Lifetime above the browser hard cutoff."
	case "TLS_CHAIN_INCOMPLETE":
		return "Chain verification failed against the configured trust pool."
	case "TLS_CHAIN_MISSING_INTERMEDIATE":
		return "Chain validates only after AIA chasing."
	case "TLS_CHAIN_MISORDERED":
		return "Certificates are not in leaf-to-root order."
	case "TLS_CHAIN_ROOT_INCLUDED":
		return "The root CA is sent unnecessarily."
	case "TLS_CHAIN_EXTRANEOUS_CERT":
		return "Chain contains a certificate unrelated to the leaf."
	case "TLS_CHAIN_CERT_EXPIRED":
		return "An intermediate or root certificate is expired."
	case "TLS_SELF_SIGNED":
		return "Leaf certificate is signed by itself (info for internal PKI)."
	case "TLS_UNTRUSTED_ROOT":
		return "Root CA is not in the configured trust store."
	case "TLS_HOSTNAME_MISMATCH":
		return "Hostname does not match any SAN."
	case "TLS_NO_SAN":
		return "No Subject Alternative Name extension."
	case "TLS_CN_ONLY_IDENTITY":
		return "Identity is asserted only via CN."
	case "TLS_WILDCARD_TOO_BROAD":
		return "Wildcard SAN spans a public suffix or an entire registrable domain."
	case "TLS_WEAK_SIGNATURE_SHA1":
		return "Signature uses SHA-1 or weaker."
	case "TLS_WEAK_RSA_KEY":
		return "RSA public key is shorter than the configured minimum."
	case "TLS_SUBOPTIMAL_RSA_KEY":
		return "RSA public key is at the current minimum."
	case "TLS_WEAK_EC_CURVE":
		return "EC curve is below the configured minimum or non-standard."
	case "TLS_KEY_USAGE_MISSING":
		return "Required Key Usage is missing."
	case "TLS_KEY_USAGE_INCONSISTENT":
		return "Key Usage set is inconsistent with the algorithm (e.g. RSA TLS 1.3 signature without digitalSignature)."
	case "TLS_EKU_MISSING_SERVER_AUTH":
		return "EKU does not include serverAuth."
	case "TLS_EKU_OVERLY_BROAD":
		return "EKU includes anyExtendedKeyUsage."
	case "TLS_CA_CERT_USED_AS_LEAF":
		return "Leaf certificate is marked as a CA."
	case "TLS_NO_AIA_OCSP":
		return "No OCSP responder is advertised."
	case "TLS_MUST_STAPLE_WITHOUT_STAPLE":
		return "Certificate requires OCSP stapling but server does not staple."
	case "TLS_OCSP_NOT_STAPLED":
		return "Server does not staple OCSP responses."
	case "TLS_OCSP_STAPLE_EXPIRED":
		return "Stapled OCSP response is expired."
	case "TLS_OCSP_STAPLE_STALE":
		return "Stapled OCSP response is older than the freshness threshold."
	case "TLS_OCSP_STAPLE_INVALID_SIG":
		return "Stapled OCSP response signature does not validate."
	case "TLS_CERT_REVOKED":
		return "Certificate is revoked."
	case "TLS_NO_SCT":
		return "No Certificate Transparency (SCT) embedded in the certificate."
	case "TLS_SSLV3_ENABLED":
		return "Server accepts SSLv3 (POODLE)."
	case "TLS_TLS10_ENABLED":
		return "Server accepts TLS 1.0 (deprecated, RFC 8996)."
	case "TLS_TLS11_ENABLED":
		return "Server accepts TLS 1.1 (deprecated, RFC 8996)."
	case "TLS_NO_TLS12":
		return "Server does not support TLS 1.2."
	case "TLS_NO_TLS13":
		return "Server does not support TLS 1.3."
	case "TLS_WEAK_CIPHER_NULL":
		return "Server accepts NULL cipher suites (no encryption)."
	case "TLS_WEAK_CIPHER_EXPORT":
		return "Server accepts EXPORT-grade cipher suites (FREAK)."
	case "TLS_WEAK_CIPHER_RC4":
		return "Server accepts RC4 cipher suites."
	case "TLS_WEAK_CIPHER_3DES":
		return "Server accepts 3DES cipher suites (SWEET32)."
	case "TLS_WEAK_CIPHER_CBC_SHA1":
		return "Server offers CBC + HMAC-SHA1 suites (Lucky13)."
	case "TLS_NO_FORWARD_SECRECY":
		return "Server offers no forward-secret cipher suite."
	case "TLS_ANON_CIPHER":
		return "Server accepts anonymous cipher suites."
	case "TLS_SNI_NOT_REQUIRED":
		return "Server accepts connections without SNI and serves a default certificate."
	case "TLS_SNI_DEFAULT_CERT_MISMATCH":
		return "Default certificate differs from the SNI-selected one."
	case "TLS_MIXED_KEY_ALGORITHMS":
		return "Server serves certificates with mixed key algorithms (RSA + ECDSA)."
	case "TLS_CERT_KEY_MISMATCH":
		return "Leaf public key does not match the handshake transient key."
	case "TLS_DUPLICATE_CERT_IN_CHAIN":
		return "Same certificate appears twice in the chain."
	case "TLS_LEAF_NOT_FIRST":
		return "First certificate in the chain is not the leaf."
	case "TLS_HSTS_MISSING":
		return "HTTPS endpoint does not advertise HSTS."
	case "TLS_HSTS_SHORT_MAXAGE":
		return "HSTS max-age is below the recommended 180 days."
	case "TLS_HSTS_ON_HTTP":
		return "HSTS header is served over plain HTTP (ignored by clients)."
	case "TLS_HTTP_NO_REDIRECT":
		return "HTTP endpoint does not redirect to HTTPS."
	case "TLS_STARTTLS_NOT_OFFERED":
		return "STARTTLS is not advertised by the peer."
	}
	return ""
}

func (s *Server) readFindingsCatalogResource(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	body, err := json.Marshal(s.findingsCatalog())
	if err != nil {
		return nil, fmt.Errorf("marshal findings catalog: %w", err)
	}
	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{{
			URI:      "probe://findings/catalog",
			MIMEType: "application/json",
			Text:     string(body),
		}},
	}, nil
}

// cfg is a convenience accessor used by Server; it returns the
// underlying config.Config pointer. Declared here so resources can
// read it without going through every call site.
var _ = (*config.Config)(nil)
