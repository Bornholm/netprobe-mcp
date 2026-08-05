package tlsdiag

import (
	"crypto/x509"
)

// ruleKeyUsageMissing flags certificates that carry no KeyUsage
// extension at all. Medium severity: well-formed certificates should
// declare their intended use.
type ruleKeyUsageMissing struct{ ruleSpec }

func newRuleKeyUsageMissing() ruleKeyUsageMissing {
	return ruleKeyUsageMissing{ruleSpec{
		id:          "TLS_KEY_USAGE_MISSING",
		severity:    SeverityMedium,
		category:    "extensions",
		title:       "Certificate has no KeyUsage extension",
		remediation: "Reissue the certificate with an explicit KeyUsage. For a TLS leaf, digitalSignature (and optionally keyEncipherment for RSA) is the minimum.",
	}}
}

func (r ruleKeyUsageMissing) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil {
		return nil
	}
	if c.Leaf.KeyUsage != 0 {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityMedium,
		Category: "extensions",
		Title:    "Certificate has no KeyUsage extension",
		Detail:   "The leaf certificate does not declare any KeyUsage. Modern issuance pipelines always include at least digitalSignature.",
		Remediation: "Reissue the certificate with an explicit KeyUsage. For a TLS " +
			"leaf, digitalSignature (and optionally keyEncipherment for RSA) is the minimum.",
		Evidence: map[string]any{
			"key_usage": decodeKeyUsage(c.Leaf.KeyUsage),
		},
	}}
}

// ruleKeyUsageNoDigitalSignature flags certificates that lack the
// digitalSignature bit — required for any leaf used in a TLS handshake.
// This is what PLAN §8.5 calls TLS_KEY_USAGE_INCONSISTENT: the
// KeyUsage set does not match the algorithm's requirements (RSA used
// as TLS 1.3 signature key without digitalSignature, etc.).
type ruleKeyUsageNoDigitalSignature struct{ ruleSpec }

func newRuleKeyUsageNoDigitalSignature() ruleKeyUsageNoDigitalSignature {
	return ruleKeyUsageNoDigitalSignature{ruleSpec{
		id:          "TLS_KEY_USAGE_INCONSISTENT",
		severity:    SeverityHigh,
		category:    "extensions",
		title:       "Leaf certificate is missing digitalSignature KeyUsage",
		remediation: "Reissue the certificate with digitalSignature in KeyUsage.",
	}}
}

func (r ruleKeyUsageNoDigitalSignature) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil {
		return nil
	}
	if c.Leaf.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		return nil
	}
	return []Finding{{
		ID:          r.ID(),
		Severity:    SeverityHigh,
		Category:    "extensions",
		Title:       "Leaf certificate is missing digitalSignature KeyUsage",
		Detail:      "TLS handshake signatures require the digitalSignature bit. Without it, strict clients may reject the certificate.",
		Remediation: "Reissue the certificate with digitalSignature in KeyUsage.",
		Evidence: map[string]any{
			"key_usage": decodeKeyUsage(c.Leaf.KeyUsage),
		},
	}}
}

// ruleEKUMissingServerAuth flags leaves whose ExtKeyUsage does not
// include serverAuth. Critical because the certificate is not
// authorised to act as a TLS server.
type ruleEKUMissingServerAuth struct{ ruleSpec }

func newRuleEKUMissingServerAuth() ruleEKUMissingServerAuth {
	return ruleEKUMissingServerAuth{ruleSpec{
		id:          "TLS_EKU_MISSING_SERVER_AUTH",
		severity:    SeverityCritical,
		category:    "extensions",
		title:       "Certificate does not declare serverAuth EKU",
		remediation: "Reissue the certificate with serverAuth in ExtKeyUsage.",
	}}
}

func (r ruleEKUMissingServerAuth) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil {
		return nil
	}
	for _, eku := range c.Leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			return nil
		}
		if eku == x509.ExtKeyUsageAny {
			// Any covers serverAuth; the rule EKU_OVERLY_BROAD will
			// flag the use of Any separately.
			return nil
		}
	}
	return []Finding{{
		ID:          r.ID(),
		Severity:    SeverityCritical,
		Category:    "extensions",
		Title:       "Certificate does not declare serverAuth EKU",
		Detail:      "The leaf certificate's ExtKeyUsage does not include serverAuth. Strict clients reject certificates without an explicit EKU matching their use.",
		Remediation: "Reissue the certificate with serverAuth in ExtKeyUsage.",
		Evidence: map[string]any{
			"ext_key_usage": decodeExtKeyUsage(c.Leaf.ExtKeyUsage),
		},
	}}
}

// ruleEKUOverlyBroad flags leaves that carry ExtKeyUsageAny. Low
// severity — usually benign but defeats the purpose of EKU scoping.
type ruleEKUOverlyBroad struct{ ruleSpec }

func newRuleEKUOverlyBroad() ruleEKUOverlyBroad {
	return ruleEKUOverlyBroad{ruleSpec{
		id:          "TLS_EKU_OVERLY_BROAD",
		severity:    SeverityLow,
		category:    "extensions",
		title:       "Certificate uses ExtKeyUsageAny",
		remediation: "Reissue with a specific set of ExtKeyUsage values (serverAuth for a TLS leaf).",
	}}
}

func (r ruleEKUOverlyBroad) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil {
		return nil
	}
	for _, eku := range c.Leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageAny {
			return []Finding{{
				ID:       r.ID(),
				Severity: SeverityLow,
				Category: "extensions",
				Title:    "Certificate uses ExtKeyUsageAny",
				Detail:   "The leaf certificate's ExtKeyUsage is set to Any. This defeats the purpose of EKU scoping and is generally only acceptable for cross-purpose certificates.",
				Remediation: "Reissue with a specific set of ExtKeyUsage values " +
					"(serverAuth for a TLS leaf).",
				Evidence: map[string]any{
					"ext_key_usage": decodeExtKeyUsage(c.Leaf.ExtKeyUsage),
				},
			}}
		}
	}
	return nil
}

// ruleMustStapleWithoutStaple fires when the leaf advertises the
// status_request TLS Feature (must-staple) but the server did not
// return a stapled OCSP response. Critical because conforming clients
// MUST reject the connection.
type ruleMustStapleWithoutStaple struct{ ruleSpec }

func newRuleMustStapleWithoutStaple() ruleMustStapleWithoutStaple {
	return ruleMustStapleWithoutStaple{ruleSpec{
		id:       "TLS_MUST_STAPLE_WITHOUT_STAPLE",
		severity: SeverityCritical,
		category: "revocation",
		title:    "Certificate requires OCSP stapling but server does not staple",
		remediation: "Either enable OCSP stapling on the server " +
			"(nginx: ssl_stapling on; ssl_stapling_verify on; with a valid " +
			"ssl_trusted_certificate) or reissue the certificate without the " +
			"must-staple extension.",
	}}
}

func (r ruleMustStapleWithoutStaple) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil || !hasMustStapleExtension(c.Leaf) {
		return nil
	}
	if c.OCSP != nil && c.OCSP.Stapled {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityCritical,
		Category: "revocation",
		Title:    "Certificate requires OCSP stapling but server does not staple",
		Detail: "The certificate carries the TLS Feature extension with " +
			"status_request (OCSP must-staple, RFC 7633), yet the server did " +
			"not include a stapled OCSP response in the handshake. Conforming " +
			"clients MUST reject this connection. The failure is invisible to " +
			"clients that ignore must-staple (e.g. curl, Go), which makes it " +
			"easy to miss in testing.",
		Remediation: "Either enable OCSP stapling on the server " +
			"(nginx: ssl_stapling on; ssl_stapling_verify on; with a valid " +
			"ssl_trusted_certificate) or reissue the certificate without the " +
			"must-staple extension.",
		Evidence: map[string]any{
			"must_staple":  true,
			"ocsp_stapled": c.OCSP != nil && c.OCSP.Stapled,
			"ocsp_servers": c.Leaf.OCSPServer,
		},
		References: []string{"https://datatracker.ietf.org/doc/html/rfc7633"},
	}}
}

// ruleOCSPStapleExpired fires when a stapled OCSP response has
// already passed its NextUpdate.
type ruleOCSPStapleExpired struct{ ruleSpec }

func newRuleOCSPStapleExpired() ruleOCSPStapleExpired {
	return ruleOCSPStapleExpired{ruleSpec{
		id:          "TLS_OCSP_STAPLE_EXPIRED",
		severity:    SeverityHigh,
		category:    "revocation",
		title:       "Stapled OCSP response is expired",
		remediation: "Refresh the OCSP staple more frequently (e.g. via the certbot renew-hook or via nginx ssl_stapling with a short refresh interval).",
	}}
}

func (r ruleOCSPStapleExpired) Evaluate(c *EvalContext) []Finding {
	if c.OCSP == nil || !c.OCSP.Stapled || !c.OCSP.StapleExpired {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityHigh,
		Category: "revocation",
		Title:    "Stapled OCSP response is expired",
		Detail:   "The server stapled an OCSP response whose NextUpdate is in the past. Conforming clients should treat the response as unreliable.",
		Remediation: "Refresh the OCSP staple more frequently (e.g. via the certbot " +
			"renew-hook or via nginx ssl_stapling with a short refresh interval).",
		Evidence: map[string]any{
			"next_update": c.OCSP.StapleNextUpdate,
			"now":         c.Now.UTC(),
		},
	}}
}

// ruleOCSPStapleStale fires when a stapled OCSP response's ThisUpdate
// is older than three days. Medium severity: not expired but the
// server is slow to refresh.
type ruleOCSPStapleStale struct{ ruleSpec }

func newRuleOCSPStapleStale() ruleOCSPStapleStale {
	return ruleOCSPStapleStale{ruleSpec{
		id:          "TLS_OCSP_STAPLE_STALE",
		severity:    SeverityMedium,
		category:    "revocation",
		title:       "Stapled OCSP response is stale",
		remediation: "Configure the server to refresh the OCSP staple at least daily. ACME clients typically trigger a refresh on each renewal.",
	}}
}

func (r ruleOCSPStapleStale) Evaluate(c *EvalContext) []Finding {
	if c.OCSP == nil || !c.OCSP.Stapled {
		return nil
	}
	if c.OCSP.StapleExpired {
		return nil // already covered by _EXPIRED
	}
	if c.OCSP.StapleAgeHours < 72 {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityMedium,
		Category: "revocation",
		Title:    "Stapled OCSP response is stale",
		Detail:   "The stapled OCSP response is older than 72 hours. The server is slow to refresh its staple.",
		Remediation: "Configure the server to refresh the OCSP staple at least " +
			"daily. ACME clients typically trigger a refresh on each renewal.",
		Evidence: map[string]any{
			"this_update": c.OCSP.StapleThisUpdate,
			"age_hours":   c.OCSP.StapleAgeHours,
		},
	}}
}

// ruleOCSPStapleInvalidSig fires when the stapled response signature
// is invalid. High severity: the response should be ignored.
type ruleOCSPStapleInvalidSig struct{ ruleSpec }

func newRuleOCSPStapleInvalidSig() ruleOCSPStapleInvalidSig {
	return ruleOCSPStapleInvalidSig{ruleSpec{
		id:          "TLS_OCSP_STAPLE_INVALID_SIG",
		severity:    SeverityHigh,
		category:    "revocation",
		title:       "Stapled OCSP response has an invalid signature",
		remediation: "Investigate why the OCSP responder signed with an unexpected issuer. Possible causes: rotated issuer certificate without re-deployment, or the server is presenting a stale staple cached against an old issuer.",
	}}
}

func (r ruleOCSPStapleInvalidSig) Evaluate(c *EvalContext) []Finding {
	if c.OCSP == nil || c.OCSP.StapleSigValid == nil || *c.OCSP.StapleSigValid {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityHigh,
		Category: "revocation",
		Title:    "Stapled OCSP response has an invalid signature",
		Detail:   "The server stapled an OCSP response that does not verify against the issuer certificate. Conforming clients should ignore the response.",
		Remediation: "Investigate why the OCSP responder signed with an unexpected " +
			"issuer. Possible causes: rotated issuer certificate without re-deployment, " +
			"or the server is presenting a stale staple cached against an old issuer.",
		Evidence: map[string]any{
			"staple_status": c.OCSP.StapleStatus,
		},
	}}
}

// ruleCertRevoked fires when the stapled OCSP response reports the
// leaf certificate as revoked. Critical: every client should reject
// the connection.
type ruleCertRevoked struct{ ruleSpec }

func newRuleCertRevoked() ruleCertRevoked {
	return ruleCertRevoked{ruleSpec{
		id:          "TLS_CERT_REVOKED",
		severity:    SeverityCritical,
		category:    "revocation",
		title:       "Leaf certificate has been revoked",
		remediation: "Replace the certificate immediately. Investigate the revocation reason (key compromise, cessation of operation, etc.) and ensure the replacement follows the appropriate CA workflow.",
	}}
}

func (r ruleCertRevoked) Evaluate(c *EvalContext) []Finding {
	if c.OCSP == nil || c.OCSP.StapleStatus != "revoked" {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityCritical,
		Category: "revocation",
		Title:    "Leaf certificate has been revoked",
		Detail:   "The stapled OCSP response reports the leaf certificate as revoked. All conforming clients must reject this connection.",
		Remediation: "Replace the certificate immediately. Investigate the " +
			"revocation reason (key compromise, cessation of operation, etc.) " +
			"and ensure the replacement follows the appropriate CA workflow.",
		Evidence: map[string]any{
			"revocation_reason": c.OCSP.RevocationReason,
			"revoked_at":        c.OCSP.RevokedAt,
		},
	}}
}
