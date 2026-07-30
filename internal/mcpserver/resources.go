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

// findingsCatalog returns the static catalogue of TLS finding IDs.
// In a future revision this would be sourced from a per-rule
// documentation table embedded in the rules files.
func (s *Server) findingsCatalog() []FindingCatalogItem {
	return []FindingCatalogItem{
		// Validity
		{ID: "TLS_CERT_EXPIRED", Severity: "critical", Category: "validity",
			Title:     "Certificate is expired",
			Rationale: "NotAfter is in the past at the time of the probe."},
		{ID: "TLS_CERT_NOT_YET_VALID", Severity: "critical", Category: "validity",
			Title:     "Certificate is not yet valid",
			Rationale: "NotBefore is in the future at the time of the probe."},
		{ID: "TLS_CERT_EXPIRING_CRITICAL", Severity: "high", Category: "validity",
			Title:     "Certificate expires within the critical window",
			Rationale: "Fewer days remain than the critical threshold."},
		{ID: "TLS_CERT_EXPIRING_SOON", Severity: "medium", Category: "validity",
			Title:     "Certificate expires soon",
			Rationale: "Fewer days remain than the warning threshold."},
		{ID: "TLS_VALIDITY_TOO_LONG", Severity: "medium", Category: "validity",
			Title:     "Certificate validity exceeds the CA/B Forum maximum",
			Rationale: "Lifetime above the configured limit."},
		// Chain
		{ID: "TLS_CHAIN_INCOMPLETE", Severity: "high", Category: "chain",
			Title:     "Certificate chain does not reach a trusted root",
			Rationale: "Verification failed against the configured trust pool."},
		{ID: "TLS_CHAIN_MISSING_INTERMEDIATE", Severity: "high", Category: "chain",
			Title:     "Intermediate CA missing from the presented chain",
			Rationale: "Chain validates only after AIA chasing."},
		{ID: "TLS_CHAIN_MISORDERED", Severity: "low", Category: "chain",
			Title: "Chain order is incorrect"},
		{ID: "TLS_CHAIN_ROOT_INCLUDED", Severity: "low", Category: "chain",
			Title: "Root CA is sent unnecessarily"},
		{ID: "TLS_CHAIN_EXTRANEOUS_CERT", Severity: "low", Category: "chain",
			Title: "Chain contains an unrelated certificate"},
		{ID: "TLS_CHAIN_CERT_EXPIRED", Severity: "critical", Category: "chain",
			Title: "An intermediate or root certificate is expired"},
		// Identity
		{ID: "TLS_HOSTNAME_MISMATCH", Severity: "critical", Category: "identity",
			Title: "Hostname does not match any SAN"},
		{ID: "TLS_NO_SAN", Severity: "high", Category: "identity",
			Title: "No Subject Alternative Name extension"},
		{ID: "TLS_CN_ONLY_IDENTITY", Severity: "high", Category: "identity",
			Title: "Identity is asserted only via CN"},
		{ID: "TLS_WILDCARD_TOO_BROAD", Severity: "high", Category: "identity",
			Title: "Wildcard SAN spans a public suffix or entire registrable domain"},
		// Crypto
		{ID: "TLS_WEAK_SIGNATURE_SHA1", Severity: "critical", Category: "crypto",
			Title: "Signature uses SHA-1 or weaker"},
		{ID: "TLS_WEAK_RSA_KEY", Severity: "critical", Category: "crypto",
			Title: "RSA public key is shorter than the configured minimum"},
		{ID: "TLS_SUBOPTIMAL_RSA_KEY", Severity: "low", Category: "crypto",
			Title: "RSA public key is at the current minimum"},
		{ID: "TLS_WEAK_EC_CURVE", Severity: "high", Category: "crypto",
			Title: "EC curve is below the configured minimum or non-standard"},
		// Revocation
		{ID: "TLS_NO_AIA_OCSP", Severity: "low", Category: "revocation",
			Title: "No OCSP responder is advertised"},
		{ID: "TLS_MUST_STAPLE_WITHOUT_STAPLE", Severity: "critical", Category: "revocation",
			Title:     "Certificate requires OCSP stapling but server does not staple",
			Rationale: "Conforming clients MUST reject the connection."},
		{ID: "TLS_OCSP_NOT_STAPLED", Severity: "low", Category: "revocation",
			Title: "Server does not staple OCSP responses"},
		{ID: "TLS_OCSP_STAPLE_EXPIRED", Severity: "high", Category: "revocation",
			Title: "Stapled OCSP response is expired"},
		{ID: "TLS_OCSP_STAPLE_STALE", Severity: "medium", Category: "revocation",
			Title: "Stapled OCSP response is older than the freshness threshold"},
		{ID: "TLS_OCSP_STAPLE_INVALID_SIG", Severity: "high", Category: "revocation",
			Title: "Stapled OCSP response signature does not validate"},
		{ID: "TLS_CERT_REVOKED", Severity: "critical", Category: "revocation",
			Title: "Certificate is revoked"},
		// Config / consistency
		{ID: "TLS_KEY_USAGE_MISSING", Severity: "medium", Category: "config",
			Title: "Required Key Usage is missing"},
		{ID: "TLS_KEY_USAGE_INCONSISTENT", Severity: "high", Category: "config",
			Title: "Key Usage inconsistent with the algorithm"},
		{ID: "TLS_EKU_MISSING_SERVER_AUTH", Severity: "critical", Category: "config",
			Title: "EKU does not include serverAuth"},
		{ID: "TLS_EKU_OVERLY_BROAD", Severity: "low", Category: "config",
			Title: "EKU includes anyExtendedKeyUsage"},
		{ID: "TLS_CA_CERT_USED_AS_LEAF", Severity: "high", Category: "config",
			Title: "Leaf certificate is marked as a CA"},
		{ID: "TLS_SNI_DEFAULT_CERT_MISMATCH", Severity: "medium", Category: "config",
			Title: "Default certificate differs from the SNI-selected one"},
		// Protocol / cipher (active phases)
		{ID: "TLS_SSLV3_ENABLED", Severity: "critical", Category: "protocol",
			Title:     "Server accepts SSLv3",
			Rationale: "Vulnerable to POODLE."},
		{ID: "TLS_TLS10_ENABLED", Severity: "high", Category: "protocol",
			Title: "Server accepts TLS 1.0 (deprecated, RFC 8996)"},
		{ID: "TLS_TLS11_ENABLED", Severity: "high", Category: "protocol",
			Title: "Server accepts TLS 1.1 (deprecated, RFC 8996)"},
		{ID: "TLS_NO_TLS12", Severity: "high", Category: "protocol",
			Title: "Server does not support TLS 1.2"},
		{ID: "TLS_NO_TLS13", Severity: "low", Category: "protocol",
			Title: "Server does not support TLS 1.3"},
		{ID: "TLS_WEAK_CIPHER_3DES", Severity: "high", Category: "protocol",
			Title: "Server offers 3DES (SWEET32)"},
		{ID: "TLS_WEAK_CIPHER_CBC_SHA1", Severity: "medium", Category: "protocol",
			Title: "Server offers CBC + HMAC-SHA1 suites (Lucky13)"},
		{ID: "TLS_NO_FORWARD_SECRECY", Severity: "high", Category: "protocol",
			Title: "Server offers no forward-secret cipher suite"},
		// STARTTLS
		{ID: "TLS_STARTTLS_NOT_OFFERED", Severity: "medium", Category: "config",
			Title: "STARTTLS is not advertised by the peer"},
		// HSTS
		{ID: "TLS_HSTS_MISSING", Severity: "medium", Category: "config",
			Title: "HTTPS endpoint does not advertise HSTS"},
		{ID: "TLS_HSTS_SHORT_MAXAGE", Severity: "low", Category: "config",
			Title: "HSTS max-age is below the recommended 180 days"},
		{ID: "TLS_HSTS_ON_HTTP", Severity: "low", Category: "config",
			Title: "HSTS header is served over plain HTTP (ignored by clients)"},
		{ID: "TLS_HTTP_NO_REDIRECT", Severity: "medium", Category: "config",
			Title: "HTTP endpoint does not redirect to HTTPS"},
	}
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
