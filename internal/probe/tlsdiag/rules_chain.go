package tlsdiag

// ruleChainIncomplete fires when the presented chain cannot reach a
// trusted root even when only the presented intermediates are used.
// High severity because the service is unusable in non-browser clients.
type ruleChainIncomplete struct{ ruleSpec }

func newRuleChainIncomplete() ruleChainIncomplete {
	return ruleChainIncomplete{ruleSpec{
		id:       "TLS_CHAIN_INCOMPLETE",
		severity: SeverityHigh,
		category: "chain",
		title:    "Certificate chain cannot reach a trusted root",
		remediation: "Inspect the presented chain. Either the server is missing an " +
			"intermediate CA, or the issuer is not in the trust store. With nginx " +
			"prefer the fullchain.pem produced by your ACME client rather than cert.pem; " +
			"with Apache use SSLCertificateChainFile or a concatenated SSLCertificateFile.",
	}}
}

func (r ruleChainIncomplete) Evaluate(c *EvalContext) []Finding {
	if c.ChainRep.Complete {
		return nil
	}
	// Missing-intermediate is a softer sub-case of incomplete; don't
	// double-report.
	if c.ChainRep.MissingIntermediate {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityHigh,
		Category: "chain",
		Title:    "Certificate chain cannot reach a trusted root",
		Detail:   "x509 verification of the presented chain failed. The leaf certificate cannot be linked to any trust anchor using only the certificates the server sent.",
		Remediation: "Inspect the presented chain. Either the server is missing an " +
			"intermediate CA, or the issuer is not in the trust store. With nginx " +
			"prefer the fullchain.pem produced by your ACME client rather than cert.pem; " +
			"with Apache use SSLCertificateChainFile or a concatenated SSLCertificateFile.",
		Evidence: map[string]any{
			"verification_error": c.ChainRep.VerificationError,
			"chain_length":       c.ChainRep.Length,
		},
		References: []string{"https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.2"},
	}}
}

// ruleChainMissingIntermediate fires when the chain can only be
// validated after the intermediate is fetched via AIA. In v1 we do
// NOT fetch the AIA — the finding is reported from the passive
// observation that the presented chain is incomplete and the leaf
// advertises an AIA URL.
type ruleChainMissingIntermediate struct{ ruleSpec }

func newRuleChainMissingIntermediate() ruleChainMissingIntermediate {
	return ruleChainMissingIntermediate{ruleSpec{
		id:       "TLS_CHAIN_MISSING_INTERMEDIATE",
		severity: SeverityHigh,
		category: "chain",
		title:    "Incomplete certificate chain: intermediate CA not served",
		remediation: "Configure the server to send the full chain " +
			"(leaf + intermediates, excluding the root). With nginx use " +
			"the fullchain.pem produced by your ACME client rather than cert.pem; " +
			"with Apache use SSLCertificateChainFile or a concatenated " +
			"SSLCertificateFile.",
	}}
}

func (r ruleChainMissingIntermediate) Evaluate(c *EvalContext) []Finding {
	if !c.ChainRep.MissingIntermediate {
		return nil
	}
	var aiaURLs []string
	if c.Leaf != nil {
		aiaURLs = c.Leaf.IssuingCertificateURL
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityHigh,
		Category: "chain",
		Title:    "Incomplete certificate chain: intermediate CA not served",
		Detail: "The server does not send the intermediate CA certificate(s). " +
			"Verification fails using only what was presented. Many non-browser " +
			"clients (Go, Java, Python requests, curl, OpenSSL s_client, embedded " +
			"stacks) will fail with 'unable to get local issuer certificate'. This " +
			"is the classic cause of 'works in my browser but not from our servers'.",
		Remediation: "Configure the server to send the full chain " +
			"(leaf + intermediates, excluding the root). With nginx use " +
			"the fullchain.pem produced by your ACME client rather than cert.pem; " +
			"with Apache use SSLCertificateChainFile or a concatenated " +
			"SSLCertificateFile.",
		Evidence: map[string]any{
			"presented_chain_length": c.ChainRep.Length,
			"verification_error":     c.ChainRep.VerificationError,
			"aia_urls":               aiaURLs,
		},
		References: []string{"https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1"},
	}}
}

// ruleChainMisordered fires when the chain is not leaf-to-root. Low
// severity because most clients tolerate it, but it violates RFC 5246.
type ruleChainMisordered struct{ ruleSpec }

func newRuleChainMisordered() ruleChainMisordered {
	return ruleChainMisordered{ruleSpec{
		id:       "TLS_CHAIN_MISORDERED",
		severity: SeverityLow,
		category: "chain",
		title:    "Certificate chain is not in leaf-to-root order",
		remediation: "Re-order the certificates served by the server. The leaf " +
			"must come first, with each subsequent certificate signing the previous one.",
	}}
}

func (r ruleChainMisordered) Evaluate(c *EvalContext) []Finding {
	if c.ChainRep.Ordered || c.ChainRep.Length < 2 {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityLow,
		Category: "chain",
		Title:    "Certificate chain is not in leaf-to-root order",
		Detail:   "Certificates in the presented chain are not in the canonical order. Most clients tolerate this but RFC 5246 requires the chain to be ordered with the leaf first and the root last.",
		Remediation: "Re-order the certificates served by the server. The leaf " +
			"must come first, with each subsequent certificate signing the previous one.",
		Evidence: map[string]any{
			"chain_length": c.ChainRep.Length,
		},
		References: []string{"https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.2"},
	}}
}

// ruleChainRootIncluded fires when the chain includes the self-signed
// root CA. Low severity: wastes bandwidth and confuses some clients.
type ruleChainRootIncluded struct{ ruleSpec }

func newRuleChainRootIncluded() ruleChainRootIncluded {
	return ruleChainRootIncluded{ruleSpec{
		id:       "TLS_CHAIN_ROOT_INCLUDED",
		severity: SeverityLow,
		category: "chain",
		title:    "Self-signed root CA is included in the served chain",
		remediation: "Configure the server to send only the leaf and intermediate " +
			"certificates, not the root. ACME clients typically emit a fullchain.pem " +
			"that already excludes the root.",
	}}
}

func (r ruleChainRootIncluded) Evaluate(c *EvalContext) []Finding {
	if !c.ChainRep.RootIncluded {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityLow,
		Category: "chain",
		Title:    "Self-signed root CA is included in the served chain",
		Detail:   "The server sends its root CA certificate as part of the chain. The root is unnecessary for validation (clients trust it by other means) and wastes bandwidth on every handshake.",
		Remediation: "Configure the server to send only the leaf and intermediate " +
			"certificates, not the root. ACME clients typically emit a fullchain.pem " +
			"that already excludes the root.",
		Evidence: map[string]any{
			"chain_length": c.ChainRep.Length,
		},
	}}
}

// ruleChainExtraneous fires when the chain contains a certificate that
// is not linked to the leaf. Low severity; usually harmless but
// indicates a misconfigured bundle.
type ruleChainExtraneous struct{ ruleSpec }

func newRuleChainExtraneous() ruleChainExtraneous {
	return ruleChainExtraneous{ruleSpec{
		id:       "TLS_CHAIN_EXTRANEOUS_CERT",
		severity: SeverityLow,
		category: "chain",
		title:    "Chain contains a certificate unrelated to the leaf",
		remediation: "Inspect the bundle and remove certificates that are not in the " +
			"leaf-to-root path. A typical misconfiguration is leaving an old " +
			"intermediate in the chain after a re-issue.",
	}}
}

func (r ruleChainExtraneous) Evaluate(c *EvalContext) []Finding {
	if len(c.ChainRep.ExtraneousCerts) == 0 {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityLow,
		Category: "chain",
		Title:    "Chain contains a certificate unrelated to the leaf",
		Detail:   "One or more certificates in the presented chain are not part of the leaf-to-root path. The server is sending extra certificates.",
		Remediation: "Inspect the bundle and remove certificates that are not in the " +
			"leaf-to-root path. A typical misconfiguration is leaving an old " +
			"intermediate in the chain after a re-issue.",
		Evidence: map[string]any{
			"extraneous_subjects": c.ChainRep.ExtraneousCerts,
		},
	}}
}

// ruleSelfSigned fires when the leaf is self-signed. High severity
// because it means the server has no chain of trust at all.
type ruleSelfSigned struct{ ruleSpec }

func newRuleSelfSigned() ruleSelfSigned {
	return ruleSelfSigned{ruleSpec{
		id:       "TLS_SELF_SIGNED",
		severity: SeverityHigh,
		category: "chain",
		title:    "Leaf certificate is self-signed",
		remediation: "Obtain a certificate from a recognised CA. For internal services, " +
			"either use an internal CA distributed via trust store, or an ACME-based " +
			"private CA with explicit trust.",
	}}
}

func (r ruleSelfSigned) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil || !isSelfSigned(c.Leaf) {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityHigh,
		Category: "chain",
		Title:    "Leaf certificate is self-signed",
		Detail:   "The leaf certificate is signed by itself rather than by a CA. Without a trusted root, no client can verify this certificate unless it has been explicitly added to a trust store.",
		Remediation: "Obtain a certificate from a recognised CA. For internal services, " +
			"either use an internal CA distributed via trust store, or an ACME-based " +
			"private CA with explicit trust.",
		Evidence: map[string]any{
			"subject":            c.Leaf.Subject.String(),
			"issuer":             c.Leaf.Issuer.String(),
			"fingerprint_sha256": fingerprintSHA256(c.Leaf.Raw),
		},
	}}
}

// ruleUntrustedRoot fires when the chain's root is not in the
// configured (system) trust store.
type ruleUntrustedRoot struct{ ruleSpec }

func newRuleUntrustedRoot() ruleUntrustedRoot {
	return ruleUntrustedRoot{ruleSpec{
		id:       "TLS_UNTRUSTED_ROOT",
		severity: SeverityHigh,
		category: "chain",
		title:    "Root CA not in the trust store",
		remediation: "Either use a publicly trusted CA, or distribute the private root " +
			"to clients via MDM, group policy, or in-application trust store.",
	}}
}

func (r ruleUntrustedRoot) Evaluate(c *EvalContext) []Finding {
	if c.ChainRep.TrustedBySystem {
		return nil
	}
	// If we couldn't even validate the chain structure, this is
	// subsumed by TLS_CHAIN_INCOMPLETE.
	if !c.ChainRep.Complete {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityHigh,
		Category: "chain",
		Title:    "Root CA not in the trust store",
		Detail:   "The chain verifies structurally but reaches a root that is not in the configured trust store. Without the root, real clients (including browsers) will reject the certificate.",
		Remediation: "Either use a publicly trusted CA, or distribute the private root " +
			"to clients via MDM, group policy, or in-application trust store.",
		Evidence: map[string]any{
			"verification_error": c.ChainRep.VerificationError,
		},
	}}
}

// ruleChainCertExpired fires when any certificate in the chain (other
// than the leaf, whose expiry is covered by ruleCertExpired) has
// already passed its NotAfter. Critical because the chain cannot
// validate when an intermediate or root is expired, even if the
// leaf itself is fresh.
type ruleChainCertExpired struct{ ruleSpec }

func newRuleChainCertExpired() ruleChainCertExpired {
	return ruleChainCertExpired{ruleSpec{
		id:          "TLS_CHAIN_CERT_EXPIRED",
		severity:    SeverityCritical,
		category:    "chain",
		title:       "An intermediate or root certificate is expired",
		remediation: "Replace the expired certificate in the chain. ACME clients usually automate this; for private CAs, audit the issuing pipeline.",
	}}
}

func (r ruleChainCertExpired) Evaluate(c *EvalContext) []Finding {
	if c.Now.IsZero() || len(c.Chain) < 2 {
		return nil
	}
	var out []Finding
	for _, cert := range c.Chain[1:] {
		if cert == nil || cert.NotAfter.IsZero() {
			continue
		}
		if !c.Now.After(cert.NotAfter) {
			continue
		}
		// Don't double-report: if the chain as a whole fails to
		// verify, ruleChainIncomplete already covers it. Only
		// report expired intermediate certs that would otherwise
		// be missed.
		subject := cert.Subject.String()
		out = append(out, Finding{
			ID:       r.ID(),
			Severity: SeverityCritical,
			Category: "chain",
			Title:    "An intermediate or root certificate is expired",
			Detail: "A non-leaf certificate in the chain (" + subject +
				") has a NotAfter in the past. Clients that verify " +
				"every certificate in the chain will reject the handshake.",
			Remediation: "Replace the expired certificate. ACME clients " +
				"automate this for public certificates; for private CAs, " +
				"audit the issuing pipeline.",
			Evidence: map[string]any{
				"subject":   subject,
				"not_after": cert.NotAfter.UTC(),
				"now":       c.Now.UTC(),
				"issuer":    cert.Issuer.String(),
			},
		})
	}
	return out
}
