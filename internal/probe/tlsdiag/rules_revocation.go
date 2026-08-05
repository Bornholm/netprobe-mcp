package tlsdiag

// ruleNoAIAOCSP fires when the leaf certificate does not advertise
// any OCSP responder URL in its Authority Information Access
// extension. Low severity: not having a responder is acceptable
// for short-lived or internal certificates, but public certificates
// are expected to provide one for revocation checking.
type ruleNoAIAOCSP struct{ ruleSpec }

func newRuleNoAIAOCSP() ruleNoAIAOCSP {
	return ruleNoAIAOCSP{ruleSpec{
		id:          "TLS_NO_AIA_OCSP",
		severity:    SeverityLow,
		category:    "revocation",
		title:       "No OCSP responder is advertised",
		remediation: "Ensure the issuing CA includes an OCSP responder URL in the certificate's Authority Information Access extension.",
	}}
}

func (r ruleNoAIAOCSP) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil {
		return nil
	}
	if len(c.Leaf.OCSPServer) > 0 {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityLow,
		Category: "revocation",
		Title:    "No OCSP responder is advertised",
		Detail: "The leaf certificate does not advertise any OCSP " +
			"responder URL. Conforming clients cannot perform OCSP-based " +
			"revocation checks against this certificate.",
		Remediation: "Reissue with a CA that includes an OCSP responder URL " +
			"in the Authority Information Access extension (most ACME " +
			"providers do this automatically).",
		Evidence: map[string]any{
			"fingerprint_sha256": fingerprintSHA256(c.Leaf.Raw),
		},
	}}
}

// ruleOCSPNotStapled fires when the certificate has an OCSP responder
// advertised and the server did not include a stapled response in the
// handshake. Low severity: stapling is a latency / privacy
// optimisation, not a correctness requirement, but its absence
// should be flagged for operators who enable must-staple (handled by
// ruleMustStapleWithoutStaple).
type ruleOCSPNotStapled struct{ ruleSpec }

func newRuleOCSPNotStapled() ruleOCSPNotStapled {
	return ruleOCSPNotStapled{ruleSpec{
		id:          "TLS_OCSP_NOT_STAPLED",
		severity:    SeverityLow,
		category:    "revocation",
		title:       "Server does not staple OCSP responses",
		remediation: "Enable OCSP stapling on the server (nginx: ssl_stapling on; ssl_stapling_verify on;).",
	}}
}

func (r ruleOCSPNotStapled) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil {
		return nil
	}
	if len(c.Leaf.OCSPServer) == 0 {
		return nil // No responder advertised; ruleNoAIAOCSP applies.
	}
	if c.OCSP != nil && c.OCSP.Stapled {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityLow,
		Category: "revocation",
		Title:    "Server does not staple OCSP responses",
		Detail: "The certificate advertises an OCSP responder but the " +
			"server did not include a stapled OCSP response. Clients must " +
			"perform their own live OCSP query, which adds latency and " +
			"leaks the client's IP to the CA.",
		Remediation: "Enable OCSP stapling on the server (nginx: " +
			"ssl_stapling on; ssl_stapling_verify on; with a valid " +
			"ssl_trusted_certificate).",
		Evidence: map[string]any{
			"ocsp_responders": c.Leaf.OCSPServer,
		},
	}}
}
