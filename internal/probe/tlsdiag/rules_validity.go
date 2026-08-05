package tlsdiag

import "time"

// ruleCertExpired detects certificates whose NotAfter is in the past.
// Critical because the service is unusable in conforming clients.
type ruleCertExpired struct{ ruleSpec }

func newRuleCertExpired() ruleCertExpired {
	return ruleCertExpired{ruleSpec{
		id:       "TLS_CERT_EXPIRED",
		severity: SeverityCritical,
		category: "validity",
		title:    "Certificate is expired",
		remediation: "Renew the certificate immediately. Configure an automated renewal " +
			"(e.g. ACME client with monitoring) to avoid recurrence.",
	}}
}

func (r ruleCertExpired) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil || c.Leaf.NotAfter.IsZero() {
		return nil
	}
	if !c.Now.After(c.Leaf.NotAfter) {
		return nil
	}
	days := -daysBetween(c.Leaf.NotAfter, c.Now)
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityCritical,
		Category: "validity",
		Title:    "Certificate is expired",
		Detail:   "The leaf certificate's NotAfter date is in the past. Conforming clients will refuse the connection.",
		Remediation: "Renew the certificate immediately. Configure an automated renewal " +
			"(e.g. ACME client with monitoring) to avoid recurrence.",
		Evidence: map[string]any{
			"not_after":          c.Leaf.NotAfter.UTC().Format(time.RFC3339),
			"now":                c.Now.UTC().Format(time.RFC3339),
			"days_past_expiry":   days,
			"fingerprint_sha256": fingerprintSHA256(c.Leaf.Raw),
		},
		References: []string{"https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5"},
	}}
}

// ruleCertNotYetValid detects certificates whose NotBefore is in the
// future. Critical because the service is unusable in conforming
// clients; usually caused by a misconfigured or skewed clock.
type ruleCertNotYetValid struct{ ruleSpec }

func newRuleCertNotYetValid() ruleCertNotYetValid {
	return ruleCertNotYetValid{ruleSpec{
		id:       "TLS_CERT_NOT_YET_VALID",
		severity: SeverityCritical,
		category: "validity",
		title:    "Certificate is not yet valid",
		remediation: "Verify that the clocks on the issuing system and the target system " +
			"are synchronised (e.g. via chrony or systemd-timesyncd). If the certificate " +
			"is genuinely being used before its validity window starts, do not deploy it.",
	}}
}

func (r ruleCertNotYetValid) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil || c.Leaf.NotBefore.IsZero() {
		return nil
	}
	if !c.Now.Before(c.Leaf.NotBefore) {
		return nil
	}
	days := daysBetween(c.Now, c.Leaf.NotBefore)
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityCritical,
		Category: "validity",
		Title:    "Certificate is not yet valid",
		Detail:   "The leaf certificate's NotBefore date is in the future. This often indicates a misconfigured client or server clock, or a certificate issued ahead of its intended use window.",
		Remediation: "Verify that the clocks on the issuing system and the target system " +
			"are synchronised (e.g. via chrony or systemd-timesyncd). If the certificate " +
			"is genuinely being used before its validity window starts, do not deploy it.",
		Evidence: map[string]any{
			"not_before":         c.Leaf.NotBefore.UTC().Format(time.RFC3339),
			"now":                c.Now.UTC().Format(time.RFC3339),
			"days_until_valid":   days,
			"fingerprint_sha256": fingerprintSHA256(c.Leaf.Raw),
		},
		References: []string{"https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5"},
	}}
}

// ruleCertExpiringCritical fires when the leaf is within
// expiring_critical_days of expiry. High severity because the failure
// mode is imminent and may have already impacted business workflows.
type ruleCertExpiringCritical struct{ ruleSpec }

func newRuleCertExpiringCritical() ruleCertExpiringCritical {
	return ruleCertExpiringCritical{ruleSpec{
		id:       "TLS_CERT_EXPIRING_CRITICAL",
		severity: SeverityHigh,
		category: "validity",
		title:    "Certificate expires within the critical window",
		remediation: "Renew the certificate now. Investigate why the renewal pipeline " +
			"did not act earlier (alert thresholds, scheduler outage, CA rate-limits).",
	}}
}

func (r ruleCertExpiringCritical) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil {
		return nil
	}
	days := daysBetween(c.Now, c.Leaf.NotAfter)
	if days < 0 {
		return nil
	}
	if days >= c.Config.ExpiringCriticalDays {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityHigh,
		Category: "validity",
		Title:    "Certificate expires within the critical window",
		Detail:   "The leaf certificate will expire in less than the configured critical window. This typically indicates that renewal automation is broken or absent.",
		Remediation: "Renew the certificate now. Investigate why the renewal pipeline " +
			"did not act earlier (alert thresholds, scheduler outage, CA rate-limits).",
		Evidence: map[string]any{
			"not_after":            c.Leaf.NotAfter.UTC().Format(time.RFC3339),
			"days_until_expiry":    days,
			"critical_window_days": c.Config.ExpiringCriticalDays,
		},
	}}
}

// ruleCertExpiringSoon fires when the leaf is within
// expiring_soon_days of expiry. Medium severity: actionable but not
// yet an outage.
type ruleCertExpiringSoon struct{ ruleSpec }

func newRuleCertExpiringSoon() ruleCertExpiringSoon {
	return ruleCertExpiringSoon{ruleSpec{
		id:       "TLS_CERT_EXPIRING_SOON",
		severity: SeverityMedium,
		category: "validity",
		title:    "Certificate will expire soon",
		remediation: "Confirm that the renewal pipeline is scheduled and within " +
			"the warning window. If no renewal is in progress, start one now.",
	}}
}

func (r ruleCertExpiringSoon) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil {
		return nil
	}
	days := daysBetween(c.Now, c.Leaf.NotAfter)
	if days < 0 {
		return nil
	}
	if days < c.Config.ExpiringCriticalDays || days >= c.Config.ExpiringSoonDays {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityMedium,
		Category: "validity",
		Title:    "Certificate will expire soon",
		Detail:   "The leaf certificate will expire within the configured warning window. Renewal automation should already be in progress; this finding surfaces it for human review.",
		Remediation: "Confirm that the renewal pipeline is scheduled and within " +
			"the warning window. If no renewal is in progress, start one now.",
		Evidence: map[string]any{
			"not_after":         c.Leaf.NotAfter.UTC().Format(time.RFC3339),
			"days_until_expiry": days,
			"warning_days":      c.Config.ExpiringSoonDays,
		},
	}}
}

// ruleValidityTooLong fires when a leaf is valid for more than
// max_validity_days (398 by default — CA/B Forum baseline). Medium.
type ruleValidityTooLong struct{ ruleSpec }

func newRuleValidityTooLong() ruleValidityTooLong {
	return ruleValidityTooLong{ruleSpec{
		id:       "TLS_VALIDITY_TOO_LONG",
		severity: SeverityMedium,
		category: "validity",
		title:    "Certificate validity exceeds CA/B Forum maximum",
		remediation: "Reissue with a validity of at most 398 days. ACME clients " +
			"configured for short-lived issuance (≤90 days) are recommended.",
	}}
}

func (r ruleValidityTooLong) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil {
		return nil
	}
	total := c.Leaf.NotAfter.Sub(c.Leaf.NotBefore).Hours() / 24
	if total <= float64(c.Config.MaxValidityDays) {
		return nil
	}
	if total > float64(c.Config.ExcessiveValidityDays) {
		// Excessive covers it; don't double-report.
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityMedium,
		Category: "validity",
		Title:    "Certificate validity exceeds CA/B Forum maximum",
		Detail:   "The leaf certificate is valid for more than 398 days. Major browsers and the CA/B Forum baseline reject certificates with longer validity periods.",
		Remediation: "Reissue with a validity of at most 398 days. ACME clients " +
			"configured for short-lived issuance (≤90 days) are recommended.",
		Evidence: map[string]any{
			"validity_days":  total,
			"max_valid_days": c.Config.MaxValidityDays,
			"not_before":     c.Leaf.NotBefore.UTC().Format(time.RFC3339),
			"not_after":      c.Leaf.NotAfter.UTC().Format(time.RFC3339),
		},
		References: []string{"https://cabforum.org/working-groups/server/baseline-requirements/documents/"},
	}}
}

// ruleValidityExcessive fires when validity exceeds the browser
// hard-cutoff (825 days). High severity: will be rejected outright by
// Safari and Chrome.
type ruleValidityExcessive struct{ ruleSpec }

func newRuleValidityExcessive() ruleValidityExcessive {
	return ruleValidityExcessive{ruleSpec{
		id:       "TLS_VALIDITY_EXCESSIVE",
		severity: SeverityHigh,
		category: "validity",
		title:    "Certificate validity exceeds the browser hard cutoff",
		remediation: "Reissue with a validity of at most 398 days. ACME clients " +
			"configured for short-lived issuance are recommended.",
	}}
}

func (r ruleValidityExcessive) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil {
		return nil
	}
	total := c.Leaf.NotAfter.Sub(c.Leaf.NotBefore).Hours() / 24
	if total <= float64(c.Config.ExcessiveValidityDays) {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityHigh,
		Category: "validity",
		Title:    "Certificate validity exceeds the browser hard cutoff",
		Detail:   "The leaf certificate is valid for more than 825 days. Safari and Chrome refuse such certificates outright.",
		Remediation: "Reissue with a validity of at most 398 days. ACME clients " +
			"configured for short-lived issuance are recommended.",
		Evidence: map[string]any{
			"validity_days":        total,
			"excessive_valid_days": c.Config.ExcessiveValidityDays,
			"not_before":           c.Leaf.NotBefore.UTC().Format(time.RFC3339),
			"not_after":            c.Leaf.NotAfter.UTC().Format(time.RFC3339),
		},
		References: []string{"https://support.apple.com/en-us/HT211025"},
	}}
}
