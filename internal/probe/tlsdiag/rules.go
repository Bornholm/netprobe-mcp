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

// Rule is a single TLS diagnostic rule. Each rule is pure, side-effect
// free and independent: easy to test, easy to disable, easy to add.
type Rule interface {
	ID() string
	Evaluate(*EvalContext) []Finding
}

// DefaultRules returns the catalogue shipped with v1. The order matches
// the file layout (validity → chain → identity → crypto → config) and
// is preserved when sorting findings by severity in the report.
func DefaultRules() []Rule {
	return []Rule{
		ruleCertExpired{},
		ruleCertNotYetValid{},
		ruleCertExpiringCritical{},
		ruleCertExpiringSoon{},
		ruleValidityTooLong{},
		ruleValidityExcessive{},

		ruleChainIncomplete{},
		ruleChainMissingIntermediate{},
		ruleChainMisordered{},
		ruleChainRootIncluded{},
		ruleChainExtraneous{},
		ruleSelfSigned{},
		ruleUntrustedRoot{},

		ruleHostnameMismatch{},
		ruleNoSAN{},
		ruleCNOnlyIdentity{},
		ruleWildcardScope{},

		ruleWeakSignature{},
		ruleWeakRSAKey{},
		ruleSuboptimalRSAKey{},
		ruleWeakECCurve{},
		ruleCACertUsedAsLeaf{},

		ruleKeyUsageMissing{},
		ruleKeyUsageNoDigitalSignature{},
		ruleEKUMissingServerAuth{},
		ruleEKUOverlyBroad{},

		ruleMustStapleWithoutStaple{},
		ruleOCSPStapleExpired{},
		ruleOCSPStapleStale{},
		ruleOCSPStapleInvalidSig{},
		ruleCertRevoked{},

		ruleLeafNotFirst{},
		ruleDuplicateCertInChain{},

		// Active-phase rules — depend on ProbeProtocols /
		// ProbeCipherSuites / CheckHSTS / StartTLS phases being
		// executed. Each returns nil when the corresponding phase
		// was not run.
		ruleTLS10Enabled{},
		ruleTLS11Enabled{},
		ruleNoTLS12{},
		ruleNoTLS13{},

		ruleWeakCipher3DES{},
		ruleWeakCipherCBCSHA1{},
		ruleNoForwardSecrecy{},

		ruleHSTSMissing{},
		ruleHSTSShortMaxAge{},
		ruleHSTSOnHTTP{},
		ruleHTTPNoRedirect{},

		ruleStartTLSNotOffered{},

		ruleSNIDefaultMismatch{},

		// Raw-ClientHello rules: depend on ProbeWeakCiphers. Each
		// rule consumes a corresponding entry from
		// rep.WeakCiphersAccepted and emits a Finding.
		ruleWeakCipherRC4{},
		ruleWeakCipherNULL{},
		ruleWeakCipherEXPORT{},
		ruleSSLV3Enabled{},
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
