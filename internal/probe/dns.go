package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/bornholm/netprobe-mcp/internal/security"
	"github.com/miekg/dns"
)

// DNSOptions is the agent-facing input for dns_probe.
type DNSOptions struct {
	Name           string `json:"name" jsonschema:"query name (domain or, for PTR, IPv4/IPv6 literal)"`
	QueryType      string `json:"query_type,omitempty" jsonschema:"A, AAAA, CNAME, MX, TXT, NS, SOA, CAA, SRV, PTR"`
	Server         string `json:"server,omitempty" jsonschema:"DNS server hostname or IP; defaults to allow-listed servers"`
	Protocol       string `json:"protocol,omitempty" jsonschema:"udp, tcp, tcp-tls"`
	Recursion      *bool  `json:"recursion,omitempty"`
	ValidateDNSSEC bool   `json:"validate_dnssec,omitempty"`
	TimeoutMs      int    `json:"timeout_ms,omitempty"`

	// Validations
	ExpectedRcode       string   `json:"expected_rcode,omitempty" jsonschema:"default NOERROR"`
	FailIfMatchesRegexp []string `json:"fail_if_matches_regexp,omitempty"`
	FailIfNotMatches    []string `json:"fail_if_not_matches_regexp,omitempty"`
	FailIfNoAnswers     bool     `json:"fail_if_no_answers,omitempty"`
}

// DNSResult is the structured agent-facing output of dns_probe.
type DNSResult struct {
	Rcode      string        `json:"rcode"`
	Answers    []DNSRecord   `json:"answers,omitempty"`
	Authority  []DNSRecord   `json:"authority,omitempty"`
	Additional []DNSRecord   `json:"additional,omitempty"`
	Flags      DNSFlags      `json:"flags"`
	ServerUsed string        `json:"server_used"`
	Protocol   string        `json:"protocol"`
	Truncated  bool          `json:"truncated"`
	DNSSEC     *DNSSECInfo   `json:"dnssec,omitempty"`
	Checks     []CheckResult `json:"checks,omitempty"`
}

// DNSRecord is one RR, stringified so the LLM gets an opaque payload.
type DNSRecord struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"`
}

// DNSFlags is the subset of dns.Msg flags surfaced to the agent.
type DNSFlags struct {
	Authoritative      bool `json:"authoritative"`
	RecursionDesired   bool `json:"recursion_desired"`
	RecursionAvailable bool `json:"recursion_available"`
}

// DNSSECInfo reports the DNSSEC posture of the answer.
//
// Note: full DNSSEC chain validation requires fetching DS records and
// verifying signatures against the root key. The miekg/dns library does
// not implement this; v1 reports that the request was sent with the DO
// bit set and any in-message signatures were parsed, but does not produce
// a definitive "secure/bogus" verdict. The Checks slice carries a
// corresponding info-level finding so the model can reason about the gap.
type DNSSECInfo struct {
	Requested      bool   `json:"requested"`
	DoBit          bool   `json:"do_bit"`
	RRSIGsParsed   int    `json:"rrsigs_parsed"`
	ChainValidated bool   `json:"chain_validated"`
	Note           string `json:"note,omitempty"`
}

// DNSProberConfig holds the structural guard-rails enforced regardless of
// any per-call options. They are derived from policy and must not be
// weakened at runtime.
type DNSProberConfig struct {
	AllowedProtocols       []string
	AllowedQueryTypes      []string
	MaxNameLength          int
	MaxLabels              int
	MaxLabelLength         int
	BlockHighEntropyLabels bool
	MaxEntropyBits         float64
	MaxResponseBytes       int
	DefaultTimeout         time.Duration
	DialTimeout            time.Duration
}

// DNSProber is the dns_probe implementation. Construct via
// NewDNSProberFromConfig.
type DNSProber struct {
	cfg DNSProberConfig

	// rootCAs, when non-nil, replaces the system trust roots for DoT
	// validation. Production deployments should leave it nil (system
	// roots); the field exists for tests and for deployments that pin
	// a private CA.
	rootCAs *x509.CertPool
}

// SetRootCAs configures a custom CA pool for DoT verification. Passing
// nil restores system roots.
func (p *DNSProber) SetRootCAs(pool *x509.CertPool) { p.rootCAs = pool }

// NewDNSProberFromConfig maps policy into the prober's runtime invariants.
func NewDNSProberFromConfig(pc config.DNSProbeConfig, dialTimeout, defaultTimeout time.Duration) *DNSProber {
	protocols := make([]string, 0, 3)
	if pc.AllowUDP {
		protocols = append(protocols, "udp")
	}
	if pc.AllowTCP {
		protocols = append(protocols, "tcp")
	}
	if pc.AllowDoT {
		protocols = append(protocols, "tcp-tls")
	}
	if len(protocols) == 0 {
		// safe-by-default: at least UDP + TCP enabled even when the
		// configuration omitted them; DoT stays opt-in.
		protocols = []string{"udp", "tcp"}
	}
	cfg := DNSProberConfig{
		AllowedProtocols:       protocols,
		AllowedQueryTypes:      upperAll(pc.AllowedQueryTypes),
		MaxNameLength:          firstNonZero(pc.MaxNameLength, 253),
		MaxLabels:              firstNonZero(pc.MaxLabels, 10),
		MaxLabelLength:         firstNonZero(pc.MaxLabelLength, 63),
		BlockHighEntropyLabels: pc.BlockHighEntropyLabels,
		MaxEntropyBits:         firstNonZeroF(pc.MaxEntropyBits, 4.0),
		MaxResponseBytes:       firstNonZero(pc.MaxResponseBytes, 4096),
		DefaultTimeout:         firstNonZeroDur(pc.Timeout, defaultTimeout),
		DialTimeout:            dialTimeout,
	}
	return &DNSProber{cfg: cfg}
}

// Validate runs all parser-level checks: name shape, query type, protocol.
// It returns nil when the inputs are well-formed. Authorization of the
// actual server and QNAME is performed by the Guard pipeline upstream.
func (p *DNSProber) Validate(opts *DNSOptions) error {
	if opts == nil {
		return errors.New("nil options")
	}
	if opts.Name == "" {
		return errors.New("name is required")
	}
	if len(opts.Name) > p.cfg.MaxNameLength {
		return fmt.Errorf("query name exceeds %d characters", p.cfg.MaxNameLength)
	}
	// Normalise for label analysis.
	name := strings.TrimSuffix(strings.ToLower(opts.Name), ".")
	if !isASCII(name) {
		return errors.New("query name must be ASCII (no IDN)")
	}
	labels := dns.SplitDomainName(name)
	if len(labels) > p.cfg.MaxLabels {
		return fmt.Errorf("query name has %d labels (max %d)", len(labels), p.cfg.MaxLabels)
	}
	for _, l := range labels {
		if l == "" {
			return errors.New("query name has an empty label")
		}
		if len(l) > p.cfg.MaxLabelLength {
			return fmt.Errorf("query name has a label of %d characters (max %d)", len(l), p.cfg.MaxLabelLength)
		}
		// Heuristic anti-exfiltration: long high-entropy labels look like
		// base32/base64-encoded payloads leaking through DNS.
		if len(l) >= 20 && shannonEntropy(l) > p.cfg.MaxEntropyBits {
			if p.cfg.BlockHighEntropyLabels {
				return fmt.Errorf("query name contains a high-entropy label (possible DNS exfiltration)")
			}
		}
	}

	qt := strings.ToUpper(defaultStr(opts.QueryType, "A"))
	if !p.queryTypeAllowed(qt) {
		return fmt.Errorf("query type %q not in the allow-list", opts.QueryType)
	}
	opts.QueryType = qt

	proto := strings.ToLower(defaultStr(opts.Protocol, "udp"))
	if !p.protocolAllowed(proto) {
		return fmt.Errorf("protocol %q not in the allow-list", opts.Protocol)
	}
	opts.Protocol = proto

	if opts.ExpectedRcode != "" {
		rc := strings.ToUpper(opts.ExpectedRcode)
		if _, ok := rcodeByName[rc]; !ok {
			return fmt.Errorf("unknown expected_rcode %q", opts.ExpectedRcode)
		}
		opts.ExpectedRcode = rc
	}

	for _, re := range opts.FailIfMatchesRegexp {
		if _, err := regexp.Compile(re); err != nil {
			return fmt.Errorf("invalid regexp in fail_if_matches_regexp: %w", err)
		}
	}
	for _, re := range opts.FailIfNotMatches {
		if _, err := regexp.Compile(re); err != nil {
			return fmt.Errorf("invalid regexp in fail_if_not_matches_regexp: %w", err)
		}
	}
	return nil
}

func (p *DNSProber) queryTypeAllowed(qt string) bool {
	if len(p.cfg.AllowedQueryTypes) == 0 {
		return true
	}
	for _, q := range p.cfg.AllowedQueryTypes {
		if q == qt {
			return true
		}
	}
	return false
}

func (p *DNSProber) protocolAllowed(proto string) bool {
	for _, p2 := range p.cfg.AllowedProtocols {
		if p2 == proto {
			return true
		}
	}
	return false
}

// Run performs a single DNS query against the already-authorised server.
// The server must already be resolved (SafeTarget) — this function never
// re-resolves the hostname and never opens a raw UDP/TCP socket without
// being routed through the dialer when needed (DoT path uses crypto/tls
// which we configure defensively).
func (p *DNSProber) Run(ctx context.Context, server *security.SafeTarget, opts DNSOptions) (*Result, error) {
	start := Now()

	res := &Result{
		Probe: "dns_probe",
		Target: Target{
			Requested:  fmt.Sprintf("%s@%s", opts.Name, server.Describe()),
			Hostname:   server.Hostname,
			ResolvedIP: server.IP.String(),
			Port:       server.Port,
			Scheme:     schemeForProtocol(opts.Protocol),
		},
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(opts.Name), qtypeFromString(opts.QueryType))
	if opts.Recursion != nil {
		m.RecursionDesired = *opts.Recursion
	} else {
		m.RecursionDesired = true
	}
	m.CheckingDisabled = false

	// EDNS0: always set an OPT record so we can advertise a buffer size
	// and (when requested) the DO bit.
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  uint16(p.cfg.MaxResponseBytes),
		},
	}
	if opts.ValidateDNSSEC {
		opt.SetDo(true)
	}
	m.Extra = append(m.Extra, opt)

	c := &dns.Client{
		Net:     protoNet(opts.Protocol),
		Timeout: p.queryTimeout(opts),
	}
	if opts.Protocol == "tcp-tls" {
		c.TLSConfig = &tls.Config{
			ServerName: server.Hostname,
			MinVersion: tls.VersionTLS12,
			RootCAs:    p.rootCAs,
		}
	}

	addr := net.JoinHostPort(server.IP.String(), strconv.Itoa(int(server.Port)))
	resp, rtt, err := c.ExchangeContext(ctx, m, addr)
	if err != nil {
		return errorResult(res, opts, server, err, time.Since(start)), nil
	}
	if resp == nil {
		return errorResult(res, opts, server, errors.New("nil response"), time.Since(start)), nil
	}

	dnsRes := &DNSResult{
		Rcode:      rcodeString(resp.Rcode),
		ServerUsed: server.IP.String(),
		Protocol:   opts.Protocol,
		Truncated:  resp.Truncated,
		Flags: DNSFlags{
			Authoritative:      resp.Authoritative,
			RecursionDesired:   resp.RecursionDesired,
			RecursionAvailable: resp.RecursionAvailable,
		},
	}
	dnsRes.Answers = recordsFromRRs(resp.Answer)
	dnsRes.Authority = recordsFromRRs(resp.Ns)
	dnsRes.Additional = recordsFromRRs(resp.Extra)

	if opts.ValidateDNSSEC {
		dnsRes.DNSSEC = extractDNSSEC(resp)
	}

	dnsRes.Checks = p.evaluateChecks(opts, dnsRes, recordsToText(resp.Answer))

	res.Success = true
	res.DNS = dnsRes
	res.DurationMs = ms(time.Since(start))
	res.Timings.DNSMs = res.DurationMs
	res.Timings.TotalMs = res.DurationMs

	// Overall success is gated by every check having passed.
	for _, c := range dnsRes.Checks {
		if !c.Passed {
			res.Success = false
			res.Error = fmt.Sprintf("check %q failed: %s", c.Name, c.Details)
			res.ErrorClass = "check_failed"
			break
		}
	}
	_ = rtt
	return res, nil
}

func (p *DNSProber) evaluateChecks(opts DNSOptions, r *DNSResult, answersText string) []CheckResult {
	var checks []CheckResult
	if opts.ExpectedRcode != "" {
		expected := strings.ToUpper(opts.ExpectedRcode)
		passed := r.Rcode == expected
		details := ""
		if !passed {
			details = fmt.Sprintf("got %s, want %s", r.Rcode, expected)
		}
		checks = append(checks, CheckResult{
			Name:    "expected_rcode",
			Passed:  passed,
			Details: details,
		})
	}
	if opts.FailIfNoAnswers {
		checks = append(checks, CheckResult{
			Name:   "fail_if_no_answers",
			Passed: len(r.Answers) > 0,
		})
	}
	for _, re := range opts.FailIfMatchesRegexp {
		matched, _ := regexp.MatchString(re, answersText)
		checks = append(checks, CheckResult{
			Name:    "fail_if_matches_regexp:" + re,
			Passed:  !matched,
			Details: ternary(matched, "regexp matched", ""),
		})
	}
	for _, re := range opts.FailIfNotMatches {
		matched, _ := regexp.MatchString(re, answersText)
		checks = append(checks, CheckResult{
			Name:    "fail_if_not_matches_regexp:" + re,
			Passed:  matched,
			Details: ternary(!matched, "regexp did not match", ""),
		})
	}
	if opts.ValidateDNSSEC && r.DNSSEC != nil {
		// Honest report: chain validation is not implemented in v1.
		checks = append(checks, CheckResult{
			Name:    "dnssec_chain_validated",
			Passed:  false, // always false in v1 — explicit limitation
			Details: "DNSSEC chain-of-trust validation is not implemented in v1; only in-message signatures were parsed",
		})
	}
	return checks
}

func (p *DNSProber) queryTimeout(opts DNSOptions) time.Duration {
	if opts.TimeoutMs > 0 {
		return time.Duration(opts.TimeoutMs) * time.Millisecond
	}
	return p.cfg.DefaultTimeout
}

func errorResult(res *Result, opts DNSOptions, server *security.SafeTarget, err error, dur time.Duration) *Result {
	res.Success = false
	res.Error = sanitizeNetErr(err)
	res.ErrorClass = classifyDNSError(err)
	res.DurationMs = ms(dur)
	res.Timings.TotalMs = res.DurationMs
	res.DNS = &DNSResult{
		Rcode:      "ERROR",
		ServerUsed: server.IP.String(),
		Protocol:   defaultStr(opts.Protocol, "udp"),
	}
	return res
}

// extractDNSSEC scans the response for RRSIG records and reports counts.
// It deliberately does NOT claim chain-of-trust validation.
func extractDNSSEC(resp *dns.Msg) *DNSSECInfo {
	info := &DNSSECInfo{DoBit: true, Note: "Chain-of-trust validation not implemented in v1"}
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.RRSIG); ok {
			info.RRSIGsParsed++
		}
	}
	for _, rr := range resp.Ns {
		if _, ok := rr.(*dns.RRSIG); ok {
			info.RRSIGsParsed++
		}
	}
	info.Requested = true
	return info
}

// recordsFromRRs converts a slice of dns.RR into our stringified form and
// applies prompt-injection sanitisation on the textual data (especially
// relevant for TXT records).
func recordsFromRRs(rrs []dns.RR) []DNSRecord {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]DNSRecord, 0, len(rrs))
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		h := rr.Header()
		data := sanitizeRRData(rr)
		if data == "" {
			continue
		}
		out = append(out, DNSRecord{
			Name: strings.TrimSuffix(h.Name, "."),
			Type: dns.TypeToString[h.Rrtype],
			TTL:  h.Ttl,
			Data: data,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeRRData(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.CNAME:
		return strings.TrimSuffix(v.Target, ".")
	case *dns.NS:
		return strings.TrimSuffix(v.Ns, ".")
	case *dns.PTR:
		return strings.TrimSuffix(v.Ptr, ".")
	case *dns.MX:
		return fmt.Sprintf("%d %s", v.Preference, strings.TrimSuffix(v.Mx, "."))
	case *dns.TXT:
		// TXT is where prompt injection would actually live; scrub
		// aggressively and bound length.
		s := strings.Join(v.Txt, " ")
		return SanitizeSnippet(truncate(s, 512))
	case *dns.SOA:
		return fmt.Sprintf("%s %d %d %d %d %d", strings.TrimSuffix(v.Mbox, "."),
			v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
	case *dns.CAA:
		return fmt.Sprintf("%d %s %q", v.Flag, v.Tag, v.Value)
	case *dns.SRV:
		return fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, strings.TrimSuffix(v.Target, "."))
	default:
		// Fallback: use the formatted header; the data is opaque to us
		// so we don't risk leaking control characters.
		return ""
	}
}

func recordsToText(rrs []dns.RR) string {
	var b strings.Builder
	for _, rr := range recordsFromRRs(rrs) {
		b.WriteString(rr.Data)
		b.WriteByte('\n')
	}
	return b.String()
}

// --- helpers ---

func protoNet(proto string) string {
	switch proto {
	case "tcp":
		return "tcp"
	case "tcp-tls":
		return "tcp-tls"
	default:
		return "udp"
	}
}

func SchemeForProtocol(proto string) string {
	switch proto {
	case "tcp":
		return "dns+tcp"
	case "tcp-tls":
		return "dot"
	default:
		return "dns"
	}
}

func schemeForProtocol(proto string) string { return SchemeForProtocol(proto) }

func qtypeFromString(name string) uint16 {
	switch strings.ToUpper(name) {
	case "A":
		return dns.TypeA
	case "AAAA":
		return dns.TypeAAAA
	case "CNAME":
		return dns.TypeCNAME
	case "MX":
		return dns.TypeMX
	case "TXT":
		return dns.TypeTXT
	case "NS":
		return dns.TypeNS
	case "SOA":
		return dns.TypeSOA
	case "CAA":
		return dns.TypeCAA
	case "SRV":
		return dns.TypeSRV
	case "PTR":
		return dns.TypePTR
	}
	return dns.TypeA
}

// rcodeString maps a numeric rcode to its mnemonic. dns.RcodeToString
// exists upstream but does not always cover extended codes in a stable way.
func rcodeString(rcode int) string {
	if name, ok := rcodeMap[rcode]; ok {
		return name
	}
	return dns.RcodeToString[rcode]
}

var rcodeMap = map[int]string{
	dns.RcodeSuccess:        "NOERROR",
	dns.RcodeFormatError:    "FORMERR",
	dns.RcodeServerFailure:  "SERVFAIL",
	dns.RcodeNameError:      "NXDOMAIN",
	dns.RcodeNotImplemented: "NOTIMP",
	dns.RcodeRefused:        "REFUSED",
	dns.RcodeYXDomain:       "YXDOMAIN",
	dns.RcodeYXRrset:        "YXRRSET",
	dns.RcodeNXRrset:        "NXRRSET",
	dns.RcodeNotAuth:        "NOTAUTH",
	dns.RcodeNotZone:        "NOTZONE",
}

// rcodeByName is the inverse mapping, used by Validate.
var rcodeByName = func() map[string]int {
	m := make(map[string]int, len(rcodeMap))
	for code, name := range rcodeMap {
		m[name] = code
	}
	return m
}()

func classifyDNSError(err error) string {
	if err == nil {
		return ""
	}
	if isTimeout(err) {
		return "timeout"
	}
	if dnsErr, ok := err.(*net.DNSError); ok {
		if dnsErr.Timeout() {
			return "timeout"
		}
		return "network"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "connection refused"):
		return "connect_refused"
	case strings.Contains(s, "no route to host"):
		return "unreachable"
	case strings.Contains(s, "dial blocked"):
		return "policy"
	case strings.Contains(s, "i/o timeout"):
		return "timeout"
	}
	return "network"
}

// shannonEntropy returns the Shannon entropy (in bits per symbol) of s.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return false
		}
	}
	return true
}

func upperAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToUpper(s)
	}
	return out
}

func firstNonZero(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func firstNonZeroF(v, def float64) float64 {
	if v <= 0 {
		return def
	}
	return v
}

func firstNonZeroDur(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func ternary[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}

// PortForProtocol is exported so the MCP handler can derive the right port
// before the Guard.Authorize call.
func PortForProtocol(proto string) uint16 {
	switch proto {
	case "tcp-tls":
		return 853
	default:
		return 53
	}
}

// portForProtocol keeps the lowercase alias for internal callers.
func portForProtocol(proto string) uint16 { return PortForProtocol(proto) }
