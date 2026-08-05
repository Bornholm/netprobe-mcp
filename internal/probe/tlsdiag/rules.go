package tlsdiag

import (
	"crypto/x509"
	"time"

	"golang.org/x/crypto/ocsp"
)

// EvalContext bundles everything a rule needs to evaluate. Keeping the
// inputs explicit makes rules trivial to test in isolation.
type EvalContext struct {
	Now                 time.Time
	Hostname            string
	Leaf                *x509.Certificate
	Chain               []*x509.Certificate
	ChainRep            ChainReport
	Handshake           HandshakeInfo
	OCSP                *OCSPReport
	Protocols           *ProtocolSupport
	Ciphers             *CipherSuiteReport
	HSTS                *HSTSReport
	StartTLS            *StartTLSReport
	SNI                 *SNIReport
	WeakCiphersAccepted []string
	Config              Config
}

// RuleMeta is the static, language-independent metadata of a Rule.
// It is exposed via the MCP findings catalogue so an LLM can resolve
// a finding ID without having to trigger the diagnostic. Every rule
// exposes its metadata via the Metadata() method.
type RuleMeta struct {
	ID          string
	Severity    Severity
	Category    string
	Title       string
	Remediation string
}

// Rule is a single TLS diagnostic rule. Each rule is pure, side-effect
// free and independent: easy to test, easy to disable, easy to add.
type Rule interface {
	ID() string
	Metadata() RuleMeta
	Evaluate(*EvalContext) []Finding
}

// ruleSpec is a reusable base for plain rules: it carries the static
// metadata (id, severity, category, title, remediation) and provides
// ID() and Metadata(). Concrete rule types embed ruleSpec and only
// implement Evaluate. This avoids duplicating metadata across the
// 40+ rules in this package and is the single source of truth for
// the MCP findings catalogue.
type ruleSpec struct {
	id          string
	severity    Severity
	category    string
	title       string
	remediation string
}

func (s ruleSpec) ID() string { return s.id }

func (s ruleSpec) Metadata() RuleMeta {
	return RuleMeta{
		ID:          s.id,
		Severity:    s.severity,
		Category:    s.category,
		Title:       s.title,
		Remediation: s.remediation,
	}
}

// DefaultRules returns the catalogue shipped with v1. The order matches
// the file layout (validity → chain → identity → crypto → config) and
// is preserved when sorting findings by severity in the report.
func DefaultRules() []Rule {
	return []Rule{
		newRuleCertExpired(),
		newRuleCertNotYetValid(),
		newRuleCertExpiringCritical(),
		newRuleCertExpiringSoon(),
		newRuleValidityTooLong(),
		newRuleValidityExcessive(),

		newRuleChainIncomplete(),
		newRuleChainMissingIntermediate(),
		newRuleChainMisordered(),
		newRuleChainRootIncluded(),
		newRuleChainExtraneous(),
		newRuleChainCertExpired(),
		newRuleSelfSigned(),
		newRuleUntrustedRoot(),

		newRuleHostnameMismatch(),
		newRuleNoSAN(),
		newRuleCNOnlyIdentity(),
		newRuleWildcardScope(),

		newRuleNoSCT(),

		newRuleWeakSignature(),
		newRuleWeakRSAKey(),
		newRuleSuboptimalRSAKey(),
		newRuleWeakECCurve(),
		newRuleCACertUsedAsLeaf(),

		newRuleKeyUsageMissing(),
		newRuleKeyUsageNoDigitalSignature(),
		newRuleEKUMissingServerAuth(),
		newRuleEKUOverlyBroad(),

		newRuleNoAIAOCSP(),
		newRuleMustStapleWithoutStaple(),
		newRuleOCSPNotStapled(),
		newRuleOCSPStapleExpired(),
		newRuleOCSPStapleStale(),
		newRuleOCSPStapleInvalidSig(),
		newRuleCertRevoked(),

		newRuleLeafNotFirst(),
		newRuleDuplicateCertInChain(),

		// Active-phase rules — depend on ProbeProtocols /
		// ProbeCipherSuites / CheckHSTS / StartTLS phases being
		// executed. Each returns nil when the corresponding phase
		// was not run.
		newRuleTLS10Enabled(),
		newRuleTLS11Enabled(),
		newRuleNoTLS12(),
		newRuleNoTLS13(),

		newRuleWeakCipher3DES(),
		newRuleWeakCipherCBCSHA1(),
		newRuleNoForwardSecrecy(),
		newRuleAnonCipher(),

		newRuleHSTSMissing(),
		newRuleHSTSShortMaxAge(),
		newRuleHSTSOnHTTP(),
		newRuleHTTPNoRedirect(),

		newRuleStartTLSNotOffered(),

		newRuleSNIDefaultMismatch(),
		newRuleSNIRequired(),

		// Raw-ClientHello rules: depend on ProbeWeakCiphers. Each
		// rule consumes a corresponding entry from
		// rep.WeakCiphersAccepted and emits a Finding.
		newRuleWeakCipherRC4(),
		newRuleWeakCipherNULL(),
		newRuleWeakCipherEXPORT(),
		newRuleSSLV3Enabled(),
	}
}

// findingsFromSortedFilter returns the input findings sorted by
// descending severity and filtered by the configured min severity.
func findingsFromSortedFilter(findings []Finding, min Severity) []Finding {
	filtered := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if !f.Severity.AtLeastAsSevere(min) {
			continue
		}
		filtered = append(filtered, f)
	}
	severityRank := map[Severity]int{
		SeverityCritical: 4,
		SeverityHigh:     3,
		SeverityMedium:   2,
		SeverityLow:      1,
		SeverityInfo:     0,
	}
	for i := 1; i < len(filtered); i++ {
		j := i
		for j > 0 && severityRank[filtered[j-1].Severity] < severityRank[filtered[j].Severity] {
			filtered[j-1], filtered[j] = filtered[j], filtered[j-1]
			j--
		}
	}
	return filtered
}

// ocspStatusToFinding maps an OCSPReport onto Findings. Used by the
// rules that need to convert OCSP outcomes into Findings.
func ocspStatusToFinding(rep *OCSPReport) (string, Severity, bool) {
	if rep == nil {
		return "", "", false
	}
	if rep.StapleStatus == "revoked" {
		return "revoked", SeverityCritical, true
	}
	if rep.StapleStatus == "serial_mismatch" {
		return "serial_mismatch", SeverityHigh, true
	}
	if rep.StapleStatus == "unparseable" {
		return "unparseable", SeverityMedium, true
	}
	return "", "", false
}

// ocspResponseStatus is a thin helper that returns resp.Status, or -1
// if resp is nil.
func ocspResponseStatus(resp *ocsp.Response) int {
	if resp == nil {
		return -1
	}
	return int(resp.Status)
}

// daysBetween returns the number of whole days between a and b.
func daysBetween(a, b time.Time) int {
	if a.After(b) {
		return -daysBetween(b, a)
	}
	return int(b.Sub(a).Hours() / 24)
}
