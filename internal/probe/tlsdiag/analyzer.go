package tlsdiag

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

// Config is the runtime configuration of an Analyzer. It is decoupled
// from config.TLSDiagConfig so the analyser can be unit-tested without
// importing the config package, and so future phases (active probes,
// custom trust anchors) can extend it independently.
type Config struct {
	Enabled bool

	TotalBudget      time.Duration
	HandshakeTimeout time.Duration

	MinTLSVersion uint16
	MaxTLSVersion uint16

	// Rule thresholds.
	ExpiringSoonDays      int
	ExpiringCriticalDays  int
	MaxValidityDays       int
	ExcessiveValidityDays int
	MinRSAKeyBits         int
	MinECKeyBits          int

	// Opt-in secondary SSRF channels. Both stay false by default
	// and the Diagnose path additionally requires the per-call flag
	// in DiagnoseOptions. They exist as config knobs so operators
	// can grant permission at the policy layer.
	AllowAIAFetch  bool
	AllowOCSPQuery bool

	// Trust anchor pool; when nil, the system pool is used.
	Roots *x509.CertPool

	// Dialer is the SafeDialer used to connect. Required.
	Dialer *security.SafeDialer

	// Guard is consulted by the secondary SSRF channels (AIA,
	// OCSP direct) before any outbound request. Optional: when nil,
	// those channels silently record a SkippedCheck and produce no
	// network traffic.
	Guard *security.Guard

	// Now returns the current time. Indirected so tests can fix a
	// deterministic clock.
	Now func() time.Time

	// MaxHSTSBytes caps the HTTP response body read for the HSTS
	// phase. Default: 4 KiB.
	MaxHSTSBytes int

	// MaxAIAFetches caps the number of AIA URLs followed in a
	// single diagnostic call. Default: 3.
	MaxAIAFetches int

	// MaxAIABytes caps the body read from a single AIA fetch.
	// Default: 4 KiB.
	MaxAIABytes int

	// MaxOCSPBytes caps the body read from a single OCSP POST.
	// Default: 4 KiB.
	MaxOCSPBytes int
}

// Analyzer orchestrates the passive TLS diagnostic.
type Analyzer struct {
	cfg    Config
	dialer *security.SafeDialer
	guard  *security.Guard
	now    func() time.Time
	rootMu sync.RWMutex
	roots  *x509.CertPool
}

// NewAnalyzer builds an Analyzer. Returns nil when cfg.Enabled is
// false; callers should treat that as "feature disabled" rather than as
// an error.
func NewAnalyzer(cfg Config) *Analyzer {
	if !cfg.Enabled {
		return nil
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Dialer == nil {
		// A nil dialer is allowed only in unit tests that exercise
		// non-network helpers; mainHandshake will panic if invoked.
	}
	if cfg.MinTLSVersion == 0 {
		cfg.MinTLSVersion = tls.VersionTLS12
	}
	if cfg.MaxTLSVersion == 0 {
		cfg.MaxTLSVersion = tls.VersionTLS13
	}
	if cfg.ExpiringSoonDays <= 0 {
		cfg.ExpiringSoonDays = 30
	}
	if cfg.ExpiringCriticalDays <= 0 {
		cfg.ExpiringCriticalDays = 7
	}
	if cfg.MaxValidityDays <= 0 {
		cfg.MaxValidityDays = 398
	}
	if cfg.ExcessiveValidityDays <= 0 {
		cfg.ExcessiveValidityDays = 825
	}
	if cfg.MinRSAKeyBits <= 0 {
		cfg.MinRSAKeyBits = 2048
	}
	if cfg.MinECKeyBits <= 0 {
		cfg.MinECKeyBits = 256
	}
	if cfg.MaxHSTSBytes <= 0 {
		cfg.MaxHSTSBytes = 4096
	}
	if cfg.MaxAIAFetches <= 0 {
		cfg.MaxAIAFetches = 3
	}
	if cfg.MaxAIABytes <= 0 {
		cfg.MaxAIABytes = 4096
	}
	if cfg.MaxOCSPBytes <= 0 {
		cfg.MaxOCSPBytes = 4096
	}
	return &Analyzer{
		cfg:    cfg,
		dialer: cfg.Dialer,
		guard:  cfg.Guard,
		now:    cfg.Now,
		roots:  cfg.Roots,
	}
}

// SetRootCAs replaces the trust anchor pool at runtime. Intended for
// tests that need to validate against a freshly generated CA without
// restarting the process.
func (a *Analyzer) SetRootCAs(pool *x509.CertPool) {
	if a == nil {
		return
	}
	a.rootMu.Lock()
	defer a.rootMu.Unlock()
	a.roots = pool
	a.cfg.Roots = pool
}

func (a *Analyzer) rootPool() *x509.CertPool {
	a.rootMu.RLock()
	defer a.rootMu.RUnlock()
	return a.roots
}

// Diagnose runs a single passive diagnostic and returns the resulting
// Report. It is the only public entry point on Analyzer.
//
// The caller is responsible for authorising the target through the
// Guard pipeline before invoking Diagnose. The SafeTarget supplied here
// is the only addressable identity the analyser is allowed to dial.
//
// Handshake failures are reported as a partial Report rather than as
// an error: an expired certificate is itself a diagnostic outcome.
// The only path that returns a non-nil error is a programmer mistake
// (missing dialer, malformed options).
func (a *Analyzer) Diagnose(target *security.SafeTarget, opts DiagnoseOptions) (*Report, error) {
	if a == nil {
		return nil, fmt.Errorf("tlsdiag: analyser is disabled")
	}
	if a.dialer == nil {
		return nil, fmt.Errorf("tlsdiag: dialer is required")
	}
	if target == nil {
		return nil, fmt.Errorf("tlsdiag: target is required")
	}
	if opts.Port == 0 {
		opts.Port = 443
	}
	budget := a.cfg.TotalBudget
	if budget <= 0 {
		budget = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	start := time.Now()
	rep := &Report{
		Target: TargetInfo{
			Host:     target.Hostname,
			Port:     opts.Port,
			Resolved: target.IP.String(),
			SNISent:  opts.ServerName,
		},
		Findings:      []Finding{},
		ChecksSkipped: AlwaysSkipped(),
		Chain:         ChainReport{PresentedCerts: []CertReport{}},
	}
	rep.Target.Port = opts.Port

	outcome, closer, hsErr := a.mainHandshake(ctx, target, opts)
	if closer != nil {
		defer closer()
	}
	rep.Handshake = buildHandshakeInfo(outcome, hsErr)
	rep.Handshake.DurationMs = time.Since(start).Milliseconds()

	if hsErr != nil {
		// Handshake failure is a result, not an error.
		rep.Verdict = "TLS handshake failed: " + sanitizeHandshakeError(hsErr)
		rep.ScanDurationMs = float64(time.Since(start).Microseconds()) / 1000
		return rep, nil
	}

	presented := outcome.ConnState.PeerCertificates
	if len(presented) == 0 {
		rep.Verdict = "no certificates presented"
		rep.ScanDurationMs = float64(time.Since(start).Microseconds()) / 1000
		return rep, nil
	}

	now := a.now()
	rep.Leaf = describeCert(presented[0], opts.ServerNameOr(target), now, opts.IncludePEM)
	rep.Chain = analyzeChain(presented, opts.ServerNameOr(target), a.rootPool(), now, opts.IncludePEM)

	if ocspBytes := outcome.ConnState.OCSPResponse; len(ocspBytes) > 0 {
		rep.OCSP = analyzeStapledOCSP(presented[0], presented, ocspBytes, now)
	}

	// Run optional active phases. Each phase gets its own bounded
	// sub-context and any failure is recorded in ChecksSkipped
	// without invalidating the rest of the report.
	a.runOptionalPhases(ctx, target, opts, outcome, presented, rep)

	// Evaluate every rule.
	ec := &EvalContext{
		Now:                 now,
		Hostname:            opts.ServerNameOr(target),
		Leaf:                presented[0],
		Chain:               presented,
		ChainRep:            rep.Chain,
		Handshake:           rep.Handshake,
		OCSP:                rep.OCSP,
		Protocols:           rep.Protocols,
		Ciphers:             rep.CipherSuites,
		HSTS:                rep.HSTS,
		StartTLS:            rep.StartTLS,
		SNI:                 rep.SNI,
		WeakCiphersAccepted: rep.WeakCiphersAccepted,
		Config:              a.cfg,
	}
	for _, rule := range DefaultRules() {
		rep.Findings = append(rep.Findings, rule.Evaluate(ec)...)
	}
	rep.Findings = findingsFromSortedFilter(rep.Findings, ParseSeverity(opts.MinSeverity))
	for _, f := range rep.Findings {
		(&rep.Summary).Add(f)
	}
	rep.Grade, rep.Score = computeGrade(rep)
	rep.Verdict = buildVerdict(rep)
	rep.ScanDurationMs = float64(time.Since(start).Microseconds()) / 1000
	return rep, nil
}

// runOptionalPhases executes the active phases requested in opts.
// Each phase runs in a derived context bounded by its own budget so
// a single misbehaving target cannot starve the global budget. A
// failure in one phase is recorded in ChecksSkipped but never aborts
// the whole diagnostic.
//
// The phase list is also responsible for trimming the AlwaysSkipped
// list: when a phase actually runs, the corresponding SkippedCheck is
// removed from the report so the LLM does not see "X not performed"
// for a check that was just performed.
func (a *Analyzer) runOptionalPhases(ctx context.Context, target *security.SafeTarget, opts DiagnoseOptions, outcome *handshakeOutcome, presented []*x509.Certificate, rep *Report) {
	if opts.StartTLS != "" {
		budget := 10 * time.Second
		pCtx, cancel := context.WithTimeout(ctx, budget)
		rep.StartTLS = a.runStartTLS(pCtx, target, opts)
		cancel()
		if rep.StartTLS != nil && rep.StartTLS.UpgradeSucceeded {
			rep.ChecksSkipped = removeSkipped(rep.ChecksSkipped, "TLS_STARTLS")
		}
	}

	if opts.ProbeProtocols {
		budget := 20 * time.Second
		pCtx, cancel := context.WithTimeout(ctx, budget)
		ps := a.probeProtocols(pCtx, target)
		cancel()
		rep.Protocols = &ps
		if ps.Probed {
			rep.ChecksSkipped = removeSkipped(rep.ChecksSkipped, "TLS_PROTOCOLS_ENUM")
		}
	}

	if opts.ProbeCipherSuites {
		budget := 30 * time.Second
		pCtx, cancel := context.WithTimeout(ctx, budget)
		cs := a.probeCipherSuites(pCtx, target)
		cancel()
		rep.CipherSuites = &cs
		rep.ChecksSkipped = removeSkipped(rep.ChecksSkipped, "TLS_CIPHER_SUITES_ENUM")
	}

	if opts.ProbeSNIBehaviour {
		budget := 10 * time.Second
		pCtx, cancel := context.WithTimeout(ctx, budget)
		// Compare against the leaf from the main handshake.
		var withSNILeaf *x509.Certificate
		if len(presented) > 0 {
			withSNILeaf = presented[0]
		}
		rep.SNI = &SNIReport{}
		*rep.SNI = a.probeSNI(pCtx, target, withSNILeaf, opts)
		cancel()
		rep.ChecksSkipped = removeSkipped(rep.ChecksSkipped, "TLS_SNI_BEHAVIOUR")
	}

	if opts.ProbeWeakCiphers {
		// Raw ClientHello phase: ~10 connections, ~5s each,
		// total budget 60s. Each weak-suite probe is independent
		// and a single failure is recorded in ChecksSkipped.
		budget := 60 * time.Second
		pCtx, cancel := context.WithTimeout(ctx, budget)
		accepted := a.probeWeakCiphers(pCtx, target)
		cancel()
		// Surface the detected weak suites in rep.OutboundRequests
		// is wrong (those are SSRF secondary channels); use a
		// dedicated field on rep.WeakCiphersAccepted.
		rep.WeakCiphersAccepted = accepted
		// Whatever the outcome, the structural blocks were
		// actually tested — remove the "untestable" SkippedCheck
		// entries for the IDs we found. If the server refused
		// everything, we leave them: absence of a finding is not
		// evidence of safety.
		for _, finding := range accepted {
			switch finding {
			case "TLS_SSLV3_ENABLED":
				rep.ChecksSkipped = removeSkipped(rep.ChecksSkipped, "TLS_SSLV3_ENABLED")
			case "TLS_WEAK_CIPHER_RC4":
				rep.ChecksSkipped = removeSkipped(rep.ChecksSkipped, "TLS_WEAK_CIPHER_RC4")
			case "TLS_WEAK_CIPHER_3DES":
				rep.ChecksSkipped = removeSkipped(rep.ChecksSkipped, "TLS_WEAK_CIPHER_3DES")
			case "TLS_WEAK_CIPHER_NULL":
				rep.ChecksSkipped = removeSkipped(rep.ChecksSkipped, "TLS_WEAK_CIPHER_NULL")
			case "TLS_WEAK_CIPHER_EXPORT":
				rep.ChecksSkipped = removeSkipped(rep.ChecksSkipped, "TLS_WEAK_CIPHER_EXPORT")
			}
		}
	}

	if opts.CheckHSTS {
		budget := 15 * time.Second
		pCtx, cancel := context.WithTimeout(ctx, budget)
		h := a.checkHSTS(pCtx, target, opts)
		cancel()
		rep.HSTS = &h
		rep.ChecksSkipped = removeSkipped(rep.ChecksSkipped, "TLS_HSTS_CHECK")
		rep.ChecksSkipped = removeSkipped(rep.ChecksSkipped, "TLS_HTTP_REDIRECT_CHECK")
	}

	if opts.AIAFetch && a.cfg.AllowAIAFetch {
		budget := 15 * time.Second
		pCtx, cancel := context.WithTimeout(ctx, budget)
		a.fetchAIA(pCtx, target, presented, rep)
		cancel()
		rep.ChecksSkipped = removeSkipped(rep.ChecksSkipped, "TLS_AIA_FETCH")
	} else if opts.AIAFetch && !a.cfg.AllowAIAFetch {
		rep.ChecksSkipped = append(rep.ChecksSkipped, SkippedCheck{
			Check:  "TLS_AIA_FETCH",
			Reason: "disabled by config (allow_aia_fetch=false)",
		})
	}

	if opts.OCSPDirect && a.cfg.AllowOCSPQuery {
		budget := 15 * time.Second
		pCtx, cancel := context.WithTimeout(ctx, budget)
		a.queryOCSPDirect(pCtx, target, presented, rep)
		cancel()
		rep.ChecksSkipped = removeSkipped(rep.ChecksSkipped, "TLS_OCSP_DIRECT_QUERY")
	} else if opts.OCSPDirect && !a.cfg.AllowOCSPQuery {
		rep.ChecksSkipped = append(rep.ChecksSkipped, SkippedCheck{
			Check:  "TLS_OCSP_DIRECT_QUERY",
			Reason: "disabled by config (allow_ocsp_query=false)",
		})
	}
}

// removeSkipped returns the list without the entry whose Check field
// matches check. The first match is removed; subsequent duplicates
// are kept (they would indicate a different reason to skip).
func removeSkipped(list []SkippedCheck, check string) []SkippedCheck {
	for i, s := range list {
		if s.Check == check {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

// ServerNameOr returns the explicit ServerName when set, otherwise the
// target hostname.
func (o DiagnoseOptions) ServerNameOr(target *security.SafeTarget) string {
	if o.ServerName != "" {
		return o.ServerName
	}
	return target.Hostname
}

// buildHandshakeInfo returns a populated HandshakeInfo from the
// observation.
func buildHandshakeInfo(outcome *handshakeOutcome, hsErr error) HandshakeInfo {
	if outcome == nil {
		return HandshakeInfo{Succeeded: false, FailureReason: "no connection"}
	}
	cs := outcome.ConnState
	hi := HandshakeInfo{
		Succeeded:        hsErr == nil,
		PeerCertificates: len(cs.PeerCertificates),
		Stapled:          len(cs.OCSPResponse) > 0,
	}
	if hsErr != nil {
		hi.FailureReason = hsErr.Error()
	}
	if v, ok := tlsVersionString[cs.Version]; ok {
		hi.Version = v
	}
	if cs.CipherSuite != 0 {
		hi.CipherSuite = tls.CipherSuiteName(cs.CipherSuite)
	}
	hi.ALPNProtocol = cs.NegotiatedProtocol
	return hi
}

// tlsVersionString maps a numeric TLS version onto its conventional
// label. Go does not expose VersionTLS10/11 on the Config surface but
// the connection state may still report them; we therefore cover the
// full numeric range.
var tlsVersionString = map[uint16]string{
	0x0300: "SSL 3.0",
	0x0301: "TLS 1.0",
	0x0302: "TLS 1.1",
	0x0303: "TLS 1.2",
	0x0304: "TLS 1.3",
}

// sanitizeHandshakeError reduces the raw error message to a stable
// one-line label usable as a verdict. Detailed errors are already
// available in HandshakeInfo.FailureReason.
func sanitizeHandshakeError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	// Truncate overly long messages.
	if len(msg) > 240 {
		msg = msg[:240] + "…"
	}
	return msg
}

// buildVerdict returns a one-line human summary of the report.
func buildVerdict(rep *Report) string {
	if rep == nil {
		return ""
	}
	switch {
	case rep.Summary.Critical > 0:
		return "TLS configuration has critical issues — service unusable for conforming clients"
	case rep.Summary.High > 0:
		return "TLS configuration has high-severity issues — review before renewal"
	case rep.Summary.Medium > 0:
		return "TLS configuration has medium-severity issues — address in next maintenance window"
	case rep.Summary.Low > 0:
		return "TLS configuration has minor issues — informational"
	case rep.Chain.Complete && rep.Handshake.Succeeded:
		return "TLS configuration looks healthy"
	default:
		return "TLS configuration analysed"
	}
}
