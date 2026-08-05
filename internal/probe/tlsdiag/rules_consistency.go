package tlsdiag

import "crypto/x509"

// ruleLeafNotFirst flags chains where the first certificate presented
// is not plausibly a leaf (no DNSNames, IPAddresses, URIs, or
// EmailAddresses). High severity: clients should always present the
// leaf first.
type ruleLeafNotFirst struct{ ruleSpec }

func newRuleLeafNotFirst() ruleLeafNotFirst {
	return ruleLeafNotFirst{ruleSpec{
		id:          "TLS_LEAF_NOT_FIRST",
		severity:    SeverityHigh,
		category:    "consistency",
		title:       "First certificate in the chain is not a leaf",
		remediation: "Inspect the server's TLS configuration and ensure the leaf certificate (the one bound to the hostname) is presented first.",
	}}
}

func (r ruleLeafNotFirst) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil || len(c.Chain) < 2 {
		return nil
	}
	// The first cert should look like a leaf. If it has none of the
	// typical leaf markers (DNSNames, IP, URI, email), it is almost
	// certainly an intermediate served by mistake.
	if looksLikeLeaf(c.Leaf) {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityHigh,
		Category: "consistency",
		Title:    "First certificate in the chain is not a leaf",
		Detail:   "The first certificate presented by the server does not look like a leaf certificate (no DNSNames, IP addresses, URIs or email addresses). Most clients tolerate this, but it indicates a misconfigured server.",
		Remediation: "Inspect the server's TLS configuration and ensure the leaf " +
			"certificate (the one bound to the hostname) is presented first.",
		Evidence: map[string]any{
			"first_subject": c.Leaf.Subject.String(),
		},
	}}
}

// ruleDuplicateCertInChain flags chains where the same certificate
// subject appears more than once. Low severity: harmless but wasteful.
type ruleDuplicateCertInChain struct{ ruleSpec }

func newRuleDuplicateCertInChain() ruleDuplicateCertInChain {
	return ruleDuplicateCertInChain{ruleSpec{
		id:          "TLS_DUPLICATE_CERT_IN_CHAIN",
		severity:    SeverityLow,
		category:    "consistency",
		title:       "Duplicate certificate in the chain",
		remediation: "Re-export the chain bundle, removing duplicates.",
	}}
}

func (r ruleDuplicateCertInChain) Evaluate(c *EvalContext) []Finding {
	dups := findDuplicate(c.Chain)
	if len(dups) == 0 {
		return nil
	}
	return []Finding{{
		ID:          r.ID(),
		Severity:    SeverityLow,
		Category:    "consistency",
		Title:       "Duplicate certificate in the chain",
		Detail:      "One or more certificates appear more than once in the presented chain. This wastes bytes and may confuse simple verifiers.",
		Remediation: "Re-export the chain bundle, removing duplicates.",
		Evidence: map[string]any{
			"duplicate_subjects": dups,
		},
	}}
}

// looksLikeLeaf returns true when the certificate has at least one of
// the typical leaf markers: DNSNames, IPAddresses, URIs or
// EmailAddresses.
func looksLikeLeaf(c *x509.Certificate) bool {
	if c == nil {
		return false
	}
	return len(c.DNSNames) > 0 ||
		len(c.IPAddresses) > 0 ||
		len(c.URIs) > 0 ||
		len(c.EmailAddresses) > 0
}
