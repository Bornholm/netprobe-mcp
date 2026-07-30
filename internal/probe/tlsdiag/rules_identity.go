package tlsdiag

import (
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// ruleHostnameMismatch fires when the requested hostname does not
// match any SAN entry. Critical because the connection cannot be
// safely identified.
type ruleHostnameMismatch struct{}

func (ruleHostnameMismatch) ID() string { return "TLS_HOSTNAME_MISMATCH" }

func (r ruleHostnameMismatch) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil || c.Hostname == "" {
		return nil
	}
	if c.ChainRep.HostnameMatches {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityCritical,
		Category: "identity",
		Title:    "Hostname does not match the certificate",
		Detail:   "The hostname used to connect does not match any SAN entry in the leaf certificate. Most clients refuse such connections, or accept them only after a manual exception.",
		Remediation: "Reissue the certificate including the correct hostname in the SAN " +
			"extension. Modern clients ignore the CN for identity matching and require SAN.",
		Evidence: map[string]any{
			"hostname":    c.Hostname,
			"san_dns":     c.Leaf.DNSNames,
			"san_ip":      ipStrings(c.Leaf.IPAddresses),
			"common_name": c.Leaf.Subject.CommonName,
		},
		References: []string{"https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.3"},
	}}
}

// ruleNoSAN fires when the certificate has no Subject Alternative Name
// extension. High severity: modern clients reject such certificates.
type ruleNoSAN struct{}

func (ruleNoSAN) ID() string { return "TLS_NO_SAN" }

func (r ruleNoSAN) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil {
		return nil
	}
	if len(c.Leaf.DNSNames) > 0 || len(c.Leaf.IPAddresses) > 0 || len(c.Leaf.URIs) > 0 || len(c.Leaf.EmailAddresses) > 0 {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityHigh,
		Category: "identity",
		Title:    "Certificate has no Subject Alternative Name extension",
		Detail:   "The certificate has no SAN extension at all. Modern browsers and libraries reject such certificates by default.",
		Remediation: "Reissue the certificate with a SAN extension that lists " +
			"every hostname or IP the service uses.",
		Evidence: map[string]any{
			"common_name": c.Leaf.Subject.CommonName,
		},
		References: []string{"https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6"},
	}}
}

// ruleCNOnlyIdentity fires when the certificate carries an identity
// only in the CN and has no SAN. Modern clients ignore CN-only
// identities.
type ruleCNOnlyIdentity struct{}

func (ruleCNOnlyIdentity) ID() string { return "TLS_CN_ONLY_IDENTITY" }

func (r ruleCNOnlyIdentity) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil {
		return nil
	}
	hasSAN := len(c.Leaf.DNSNames) > 0 || len(c.Leaf.IPAddresses) > 0 || len(c.Leaf.URIs) > 0 || len(c.Leaf.EmailAddresses) > 0
	if hasSAN {
		return nil
	}
	if c.Leaf.Subject.CommonName == "" {
		return nil
	}
	return []Finding{{
		ID:          r.ID(),
		Severity:    SeverityHigh,
		Category:    "identity",
		Title:       "Identity is only in the Common Name, not in the SAN",
		Detail:      "The certificate carries identity only in the Subject CN. RFC 6125 §6.4.4 and modern browsers ignore CN-only identities when SAN is absent.",
		Remediation: "Reissue the certificate with a SAN extension.",
		Evidence: map[string]any{
			"common_name": c.Leaf.Subject.CommonName,
		},
	}}
}

// ruleWildcardScope flags wildcard certificates that span a public
// suffix (e.g. *.com, *.co.uk) or that cover an entire registrable
// domain (e.g. *.example.com). Both are stronger-issued when needed
// and weaker-issued when not.
type ruleWildcardScope struct{}

func (ruleWildcardScope) ID() string { return "TLS_WILDCARD_TOO_BROAD" }

func (r ruleWildcardScope) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil {
		return nil
	}
	var out []Finding
	for _, name := range c.Leaf.DNSNames {
		if !strings.HasPrefix(name, "*.") {
			continue
		}
		base := strings.TrimPrefix(name, "*.")
		if base == "" {
			continue
		}
		// publicsuffix.EffectiveTLDPlusOne fails when the input IS a
		// public suffix. That is exactly the case we want to flag.
		if _, err := publicsuffix.EffectiveTLDPlusOne(base); err != nil {
			out = append(out, Finding{
				ID:       r.ID(),
				Severity: SeverityHigh,
				Category: "identity",
				Title:    "Wildcard SAN spans a public suffix",
				Detail: "The SAN " + name + " covers an entire public suffix. Such a " +
					"certificate should never be issued and would allow impersonation " +
					"of unrelated domains sharing that suffix.",
				Remediation: "Reissue with specific hostnames or a wildcard scoped " +
					"to a domain you control.",
				Evidence: map[string]any{"san": name},
			})
			continue
		}
		if labels := strings.Count(base, "."); labels == 1 {
			out = append(out, Finding{
				ID:       r.ID(),
				Severity: SeverityMedium,
				Category: "identity",
				Title:    "Broad wildcard certificate",
				Detail: "The SAN " + name + " covers every subdomain of a " +
					"registrable domain. If the private key is compromised, every " +
					"subdomain is impersonable.",
				Remediation: "Prefer per-hostname certificates issued automatically " +
					"via ACME, scoping key exposure per service.",
				Evidence: map[string]any{"san": name},
			})
		}
	}
	return out
}

func ipStrings(ips []net.IP) []string {
	if len(ips) == 0 {
		return nil
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}
