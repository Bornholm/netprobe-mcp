package tlsdiag

import "crypto/x509"

// sctExtensionOID is the OID for the CT Precertificate Signed
// Certificate Timestamps List extension (RFC 6962 §3.3).
const sctExtensionOID = "1.3.6.1.4.1.11129.2.4.2"

// hasSCTExtension returns true when the certificate carries at
// least one Signed Certificate Timestamp. The SCT list extension is
// optional but expected on public certificates (Chrome refuses
// certificates without it after April 2018).
func hasSCTExtension(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	for _, ext := range cert.Extensions {
		if ext.Id.String() == sctExtensionOID {
			return true
		}
	}
	return false
}

// ruleNoSCT fires when the leaf has no embedded Signed Certificate
// Timestamps. Low severity for legacy certificates, but on
// certificates issued after the CT mandate (Chrome requires SCTs
// since April 2018) the absence is a misconfiguration that will be
// silently rejected by browsers.
type ruleNoSCT struct{ ruleSpec }

func newRuleNoSCT() ruleNoSCT {
	return ruleNoSCT{ruleSpec{
		id:          "TLS_NO_SCT",
		severity:    SeverityLow,
		category:    "chain",
		title:       "No Certificate Transparency (SCT) embedded in the certificate",
		remediation: "Reissue via a CA that logs to Certificate Transparency logs (the major public CAs do this by default).",
	}}
}

func (r ruleNoSCT) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil {
		return nil
	}
	if hasSCTExtension(c.Leaf) {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityLow,
		Category: "chain",
		Title:    "No Certificate Transparency (SCT) embedded in the certificate",
		Detail: "The leaf certificate does not carry the CT Precertificate " +
			"Signed Certificate Timestamps extension (OID 1.3.6.1.4.1.11129.2.4.2). " +
			"Chrome requires SCTs in every public certificate issued after " +
			"April 2018 and silently refuses connections without them.",
		Remediation: "Reissue via a CA that logs to Certificate Transparency logs " +
			"(the major public CAs do this by default).",
		Evidence: map[string]any{
			"fingerprint_sha256": fingerprintSHA256(c.Leaf.Raw),
			"issuer":             c.Leaf.Issuer.String(),
		},
	}}
}
