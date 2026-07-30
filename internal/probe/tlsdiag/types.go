// Package tlsdiag provides a passive TLS diagnostic tool. It performs a
// single handshake against an authorized target and analyses the leaf
// certificate, the presented chain, and any stapled OCSP response. The
// analyser is intentionally conservative: every active technique that
// would require additional outbound traffic (AIA chasing, direct OCSP
// queries, protocol enumeration, SNI-vs-default comparison) is disabled
// in v1 to keep the diagnostic surface strictly equal to one inbound
// connection.
package tlsdiag

import (
	"crypto/x509"
	"time"
)

// Severity classifies findings by impact. The ordering is meaningful
// (rules are sorted by severity) and used by the consumer to filter
// reports.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// AllSeverities returns the known severities in decreasing impact order.
// Used to filter reports and to seed UI dropdowns in client tooling.
func AllSeverities() []Severity {
	return []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
	}
}

// ParseSeverity returns the matching severity, defaulting to Info when
// the input is unknown. This lenient behaviour is intentional: a bogus
// value passed by an LLM should not crash the diagnostic.
func ParseSeverity(s string) Severity {
	switch s {
	case string(SeverityCritical):
		return SeverityCritical
	case string(SeverityHigh):
		return SeverityHigh
	case string(SeverityMedium):
		return SeverityMedium
	case string(SeverityLow):
		return SeverityLow
	case string(SeverityInfo):
		return SeverityInfo
	}
	return SeverityInfo
}

// AtLeastAsSevere returns true when a is more severe than b.
func (a Severity) AtLeastAsSevere(b Severity) bool {
	rank := map[Severity]int{
		SeverityInfo:     0,
		SeverityLow:      1,
		SeverityMedium:   2,
		SeverityHigh:     3,
		SeverityCritical: 4,
	}
	return rank[a] >= rank[b]
}

// Finding is the unit of diagnostic output. Findings are stable by ID
// so that an LLM consumer can reason about them across runs ("is this
// finding new?") and so tests can assert exact identifiers without
// brittleness on phrasing.
type Finding struct {
	ID          string         `json:"id" jsonschema:"stable identifier, e.g. TLS_CERT_EXPIRED"`
	Severity    Severity       `json:"severity"`
	Category    string         `json:"category" jsonschema:"validity|chain|identity|crypto|extensions|revocation|config|consistency"`
	Title       string         `json:"title"`
	Detail      string         `json:"detail"`
	Remediation string         `json:"remediation" jsonschema:"concrete corrective action"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	References  []string       `json:"references,omitempty"`
}

// FindingCounts is a coarse histogram used for the report summary.
type FindingCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// Add increments the histogram for f's severity.
func (c *FindingCounts) Add(f Finding) {
	c.Total++
	switch f.Severity {
	case SeverityCritical:
		c.Critical++
	case SeverityHigh:
		c.High++
	case SeverityMedium:
		c.Medium++
	case SeverityLow:
		c.Low++
	case SeverityInfo:
		c.Info++
	}
}

// TargetInfo describes the destination of the diagnostic. It is
// captured from the SafeTarget so that audit logs can identify the
// host without re-resolving.
type TargetInfo struct {
	Host     string `json:"host"`
	Port     uint16 `json:"port"`
	Resolved string `json:"resolved,omitempty" jsonschema:"the IP that was actually connected to"`
	SNISent  string `json:"sni_sent,omitempty"`
}

// HandshakeInfo captures the high-level result of the TLS handshake.
// It is set even on failure, because handshake failures are a valid
// diagnostic outcome (expired leaf, wrong hostname, etc.).
type HandshakeInfo struct {
	Version          string `json:"version" jsonschema:"TLS 1.2|TLS 1.3"`
	CipherSuite      string `json:"cipher_suite,omitempty"`
	ALPNProtocol     string `json:"alpn_protocol,omitempty"`
	PeerCertificates int    `json:"peer_certificates"`
	Stapled          bool   `json:"stapled_ocsp"`
	Succeeded        bool   `json:"succeeded"`
	FailureReason    string `json:"failure_reason,omitempty"`
	DurationMs       int64  `json:"duration_ms"`
}

// CertReport describes one certificate in the presented chain.
type CertReport struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	DaysUntilExpiry    float64   `json:"days_until_expiry"`
	ValidityDays       float64   `json:"validity_days"`
	Expired            bool      `json:"expired"`
	NotYetValid        bool      `json:"not_yet_valid"`
	SelfSigned         bool      `json:"self_signed"`
	IsCA               bool      `json:"is_ca"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	IPAddresses        []string  `json:"ip_addresses,omitempty"`
	EmailAddresses     []string  `json:"email_addresses,omitempty"`
	URIs               []string  `json:"uris,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	PublicKeyBits      int       `json:"public_key_bits"`
	PublicKeyCurve     string    `json:"public_key_curve,omitempty"`
	KeyUsage           []string  `json:"key_usage,omitempty"`
	ExtKeyUsage        []string  `json:"ext_key_usage,omitempty"`
	OCSPServers        []string  `json:"ocsp_servers,omitempty"`
	IssuingCertURLs    []string  `json:"issuing_certificate_urls,omitempty"`
	CRLDistPoints      []string  `json:"crl_distribution_points,omitempty"`
	MustStaple         bool      `json:"must_staple"`
	SubjectKeyID       string    `json:"subject_key_id,omitempty"`
	AuthorityKeyID     string    `json:"authority_key_id,omitempty"`
	FingerprintSHA256  string    `json:"fingerprint_sha256"`
	SPKISHA256         string    `json:"spki_sha256" jsonschema:"base64 SPKI pin"`
	PEM                string    `json:"pem,omitempty" jsonschema:"included only when explicitly requested"`
}

// ChainReport summarises the verification result of the presented
// certificate chain.
type ChainReport struct {
	Length              int          `json:"length"`
	PresentedCerts      []CertReport `json:"presented_certs"`
	Complete            bool         `json:"complete" jsonschema:"chain reaches a trusted root"`
	TrustedBySystem     bool         `json:"trusted_by_system"`
	VerificationError   string       `json:"verification_error,omitempty"`
	Ordered             bool         `json:"ordered" jsonschema:"certs are in leaf-to-root order"`
	RootIncluded        bool         `json:"root_included" jsonschema:"self-signed root sent unnecessarily"`
	MissingIntermediate bool         `json:"missing_intermediate" jsonschema:"chain only validated after fetching the intermediate via AIA; not done in v1"`
	ExtraneousCerts     []string     `json:"extraneous_certs,omitempty"`
	VerifiedChains      [][]string   `json:"verified_chains,omitempty"`
	HostnameMatches     bool         `json:"hostname_matches"`
	MatchedName         string       `json:"matched_name,omitempty"`
}

// OCSPReport captures the analysis of any stapled OCSP response. The
// analyser never issues an outbound OCSP query in v1 unless
// DiagnoseOptions.OCSPDirect and cfg.AllowOCSPQuery are both true,
// in which case DirectQueried/DirectStatus are populated.
type OCSPReport struct {
	Stapled          bool       `json:"stapled"`
	StapleStatus     string     `json:"staple_status,omitempty" jsonschema:"good|revoked|unknown|unparseable|serial_mismatch"`
	StapleThisUpdate *time.Time `json:"staple_this_update,omitempty"`
	StapleNextUpdate *time.Time `json:"staple_next_update,omitempty"`
	StapleAgeHours   float64    `json:"staple_age_hours,omitempty"`
	StapleExpired    bool       `json:"staple_expired"`
	StapleSigValid   *bool      `json:"staple_signature_valid,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason string     `json:"revocation_reason,omitempty"`

	// DirectQueried is true when the analyser issued a POST to the
	// OCSP responder. The status string is recorded in DirectStatus;
	// transport-level errors land in DirectError (truncated).
	DirectQueried bool   `json:"direct_queried,omitempty"`
	DirectStatus  string `json:"direct_status,omitempty" jsonschema:"good|revoked|unknown"`
	DirectError   string `json:"direct_error,omitempty"`
}

// SkippedCheck documents a control that could not be evaluated. The
// presence of an entry in this list is informational, not a defect:
// every skipped check has a concrete reason tied to v1 scope.
type SkippedCheck struct {
	Check  string `json:"check" jsonschema:"stable identifier, e.g. TLS_SSLV3_ENABLED"`
	Reason string `json:"reason"`
}

// DiagnoseOptions is the public input to Analyzer.Diagnose.
type DiagnoseOptions struct {
	Host        string `json:"host" jsonschema:"hostname to diagnose"`
	Port        uint16 `json:"port,omitempty"`
	ServerName  string `json:"server_name,omitempty" jsonschema:"SNI value; defaults to host"`
	IncludePEM  bool   `json:"include_pem,omitempty" jsonschema:"include PEM-encoded leaf certificate"`
	MinSeverity string `json:"min_severity,omitempty" jsonschema:"filter findings: info|low|medium|high|critical"`

	// Active phases — opt-in. Each one consumes additional rate-limit
	// slots and an additional handshake (or HTTP request). The analyser
	// rejects requests when the corresponding flag is set but the
	// underlying phase is not compiled in.
	//
	// All flags default to false. Active probes are listed in
	// AlwaysSkipped() until they are actually performed: skipping them
	// keeps the report honest about what was measured.

	// ProbeProtocols opens up to four additional handshakes (one per
	// TLS version 1.0/1.1/1.2/1.3) to enumerate support.
	ProbeProtocols bool `json:"probe_protocols,omitempty"`

	// ProbeCipherSuites opens additional handshakes to classify the
	// cipher suites the server is willing to negotiate (forward
	// secrecy, CBC-only, etc.).
	ProbeCipherSuites bool `json:"probe_cipher_suites,omitempty"`

	// ProbeSNIBehaviour issues a second handshake without SNI to
	// detect a mismatch between the default and SNI-selected
	// certificates. Mismatches reveal virtual-host confusion and
	// are particularly relevant for legacy clients that do not
	// emit SNI (TLS §3 of RFC 6066). The phase is opt-in because
	// it adds a full handshake to every call.
	ProbeSNIBehaviour bool `json:"probe_sni_behaviour,omitempty"`

	// ProbeWeakCiphers forges raw TLS ClientHellos to detect
	// acceptance of cipher suites and protocol versions that
	// crypto/tls in Go cannot probe (SSLv3, RC4, 3DES, NULL,
	// EXPORT). The phase is opt-in because it opens one TCP
	// connection per cipher under test (~10 connections) and
	// never sends application data.
	ProbeWeakCiphers bool `json:"probe_weak_ciphers,omitempty"`

	// CheckHSTS issues a single HTTP request on port 80 (or the
	// configured HTTPPort) to inspect HSTS and the HTTP->HTTPS
	// redirect behaviour.
	CheckHSTS bool `json:"check_hsts,omitempty"`

	// HTTPPort overrides the default port (80) for the HSTS phase.
	HTTPPort uint16 `json:"http_port,omitempty"`

	// StartTLS upgrades a plaintext connection to TLS using a
	// protocol-specific handshake. Allowed values: "smtp", "imap",
	// "pop3", "ftp", "postgres". Empty disables the phase.
	StartTLS string `json:"start_tls,omitempty"`

	// AIAFetch enables chasing the Authority Information Access
	// URL to retrieve missing intermediate certificates. v1 still
	// requires the operator to also enable AllowAIAFetch in the
	// configuration: both must be true.
	AIAFetch bool `json:"aia_fetch,omitempty"`

	// OCSPDirect issues a single POST request to the OCSP responder
	// listed in the leaf certificate. v1 still requires
	// AllowOCSPQuery in the configuration.
	OCSPDirect bool `json:"ocsp_direct,omitempty"`
}

// Report is the top-level diagnostic output.
type Report struct {
	Target         TargetInfo     `json:"target"`
	Verdict        string         `json:"verdict" jsonschema:"one-line human-readable summary"`
	Grade          string         `json:"grade,omitempty" jsonschema:"letter grade: A+|A|B|C|D|E|F"`
	Score          int            `json:"score,omitempty" jsonschema:"0-100 score"`
	Findings       []Finding      `json:"findings" jsonschema:"issues ordered by severity, most severe first"`
	Summary        FindingCounts  `json:"summary"`
	Handshake      HandshakeInfo  `json:"handshake"`
	Chain          ChainReport    `json:"chain"`
	Leaf           CertReport     `json:"leaf"`
	OCSP           *OCSPReport    `json:"ocsp,omitempty"`
	ScanDurationMs float64        `json:"scan_duration_ms"`
	ChecksSkipped  []SkippedCheck `json:"checks_skipped,omitempty"`

	// OutboundRequests records every URL the diagnostic fetched at the
	// request of the target (AIA chasing, direct OCSP query). The
	// URL is attacker-controlled — taken from the certificate — so
	// every such request must be auditable. Mirrors PLAN.md §11.1.
	OutboundRequests []OutboundRequest `json:"outbound_requests,omitempty"`

	// Active-phase results. Each is nil when the phase was disabled or
	// not run; the presence of a populated value indicates the phase
	// was actually executed.

	// Protocols enumerates TLS versions the server accepted. Nil when
	// ProbeProtocols was not requested.
	Protocols *ProtocolSupport `json:"protocols,omitempty"`

	// CipherSuites classifies the suites the server negotiated.
	// Nil when ProbeCipherSuites was not requested.
	CipherSuites *CipherSuiteReport `json:"cipher_suites,omitempty"`

	// HSTS records the result of the HSTS / HTTP redirect check.
	// Nil when CheckHSTS was not requested.
	HSTS *HSTSReport `json:"hsts,omitempty"`

	// StartTLS records the outcome of the STARTTLS upgrade. Nil when
	// the StartTLS field was empty.
	StartTLS *StartTLSReport `json:"start_tls,omitempty"`

	// SNI records the result of the SNI-vs-default probe. Nil when
	// ProbeSNIBehaviour was not requested.
	SNI *SNIReport `json:"sni,omitempty"`

	// WeakCiphersAccepted lists the finding IDs whose raw
	// ClientHello probe was accepted by the server. Populated
	// only when ProbeWeakCiphers is set. Each entry corresponds
	// to one of the findings catalogued in rules_active.go
	// (TLS_WEAK_CIPHER_RC4 / _3DES / _NULL / _EXPORT,
	// TLS_SSLV3_ENABLED).
	WeakCiphersAccepted []string `json:"weak_ciphers_accepted,omitempty"`
}

// OutboundRequest describes one secondary HTTP request emitted by the
// diagnostic at the target's request. Purpose is either "aia_fetch"
// or "ocsp_query"; Outcome is "success", "denied", or "error". The
// combination lets post-incident analysis tell "we fetched X" from
// "we tried to fetch X but were denied" at a glance.
type OutboundRequest struct {
	URL       string `json:"url"`
	Purpose   string `json:"purpose,omitempty"`
	Outcome   string `json:"outcome"`
	BytesRead int64  `json:"bytes_read,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// ProtocolSupport maps each probed TLS version to a TriState. The
// presence of this struct in a Report means ProbeProtocols was
// executed; the field Probed stays true for clarity.
type ProtocolSupport struct {
	SSLv30 TriState `json:"sslv3"`
	TLS10  TriState `json:"tls1_0"`
	TLS11  TriState `json:"tls1_1"`
	TLS12  TriState `json:"tls1_2"`
	TLS13  TriState `json:"tls1_3"`
	Probed bool     `json:"probed"`
	Note   string   `json:"note,omitempty"`
}

// TriState distinguishes "not supported" from "not tested" — an
// important distinction for an LLM consumer that might otherwise
// conclude a feature is absent.
type TriState string

const (
	TriYes     TriState = "supported"
	TriNo      TriState = "not_supported"
	TriUnknown TriState = "not_tested"
)

// CipherSuiteReport groups the cipher-suite findings of the
// enumeration phase. Each bool field is true when the corresponding
// class was at least offered by the server.
type CipherSuiteReport struct {
	ForwardSecrecy     bool     `json:"forward_secrecy"`
	WeakCBCSHA1        bool     `json:"weak_cbc_sha1"`
	Weak3DES           bool     `json:"weak_3des"`
	WeakRC4            bool     `json:"weak_rc4"`
	WeakNULL           bool     `json:"weak_null"`
	WeakExport         bool     `json:"weak_export"`
	WeakAnon           bool     `json:"weak_anon"`
	MixedKeyAlgorithms bool     `json:"mixed_key_algorithms"`
	NegotiatedGroups   []string `json:"negotiated_groups,omitempty"`
	Note               string   `json:"note,omitempty"`
}

// HSTSReport captures the result of the HSTS / HTTP redirect check.
type HSTSReport struct {
	HTTPSRedirect           bool   `json:"https_redirect"`
	StrictTransportSecurity string `json:"strict_transport_security,omitempty"`
	MaxAgeSeconds           int64  `json:"max_age_seconds,omitempty"`
	IncludeSubDomains       bool   `json:"include_sub_domains"`
	Preload                 bool   `json:"preload"`
	HSTSShortMaxAge         bool   `json:"hsts_short_max_age"`
	HSTSOnHTTP              bool   `json:"hsts_on_http"`
	Note                    string `json:"note,omitempty"`
}

// StartTLSReport captures the outcome of the STARTTLS upgrade. A
// nil-valued NegotiatedVersion indicates the upgrade failed (see
// FailureReason for the cause).
type StartTLSReport struct {
	Protocol          string `json:"protocol"`
	Banner            string `json:"banner,omitempty"`
	UpgradeSucceeded  bool   `json:"upgrade_succeeded"`
	NegotiatedVersion string `json:"negotiated_version,omitempty"`
	NegotiatedCipher  string `json:"negotiated_cipher,omitempty"`
	FailureReason     string `json:"failure_reason,omitempty"`
}

// Sanitized returns a copy of the report with PEM-bearing fields
// stripped. The MCP layer uses this when the tool call did not set
// IncludePEM, so that sensitive data never leaves the process without
// an explicit opt-in.
func (r *Report) Sanitized() Report {
	out := *r
	out.Leaf.PEM = ""
	for i := range out.Chain.PresentedCerts {
		out.Chain.PresentedCerts[i].PEM = ""
	}
	return out
}

// TimeProvider returns the current time. Indirected so tests can fix a
// deterministic clock.
type TimeProvider func() time.Time

// DefaultTimeProvider returns time.Now.
func DefaultTimeProvider() TimeProvider {
	return func() time.Time { return time.Now() }
}

// RootCAPoolProvider returns the trust anchor pool to use for chain
// verification. The default implementation uses the system pool, but
// tests inject a custom pool via Analyzer.SetRootCAs.
type RootCAPoolProvider func() *x509.CertPool
