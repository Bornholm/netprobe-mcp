// Rules that depend on the active phases (protocol enumeration,
// cipher suite enumeration, HSTS check, STARTTLS upgrade). Each
// rule returns nil when the corresponding phase was not executed.

package tlsdiag

import (
	"crypto/x509"
	"strings"
)

// ruleTLS10Enabled fires when the protocol-enumeration phase
// detected TLS 1.0 acceptance. RFC 8996 deprecates TLS 1.0.
type ruleTLS10Enabled struct{}

func (ruleTLS10Enabled) ID() string { return "TLS_TLS10_ENABLED" }

func (r ruleTLS10Enabled) Evaluate(c *EvalContext) []Finding {
	if c.Protocols == nil || c.Protocols.TLS10 != TriYes {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityHigh,
		Category: "protocol",
		Title:    "Server accepts TLS 1.0",
		Detail: "TLS 1.0 is deprecated (RFC 8996) and suffers from " +
			"several known cryptographic weaknesses (BEAST, POODLE). " +
			"Most modern clients prefer TLS 1.2+.",
		Remediation: "Disable TLS 1.0 on the server (e.g. nginx: " +
			"ssl_protocols TLSv1.2 TLSv1.3;).",
		Evidence:   map[string]any{"negotiated": "TLS 1.0"},
		References: []string{"https://datatracker.ietf.org/doc/html/rfc8996"},
	}}
}

// ruleTLS11Enabled fires when TLS 1.1 is accepted. Deprecated since
// RFC 8996 (March 2021).
type ruleTLS11Enabled struct{}

func (ruleTLS11Enabled) ID() string { return "TLS_TLS11_ENABLED" }

func (r ruleTLS11Enabled) Evaluate(c *EvalContext) []Finding {
	if c.Protocols == nil || c.Protocols.TLS11 != TriYes {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityHigh,
		Category: "protocol",
		Title:    "Server accepts TLS 1.1",
		Detail: "TLS 1.1 is deprecated (RFC 8996). Modern clients prefer " +
			"TLS 1.2 or TLS 1.3.",
		Remediation: "Disable TLS 1.1 on the server (e.g. nginx: " +
			"ssl_protocols TLSv1.2 TLSv1.3;).",
		Evidence:   map[string]any{"negotiated": "TLS 1.1"},
		References: []string{"https://datatracker.ietf.org/doc/html/rfc8996"},
	}}
}

// ruleNoTLS12 fires when the server does not negotiate TLS 1.2.
// Some legacy clients still require it.
type ruleNoTLS12 struct{}

func (ruleNoTLS12) ID() string { return "TLS_NO_TLS12" }

func (r ruleNoTLS12) Evaluate(c *EvalContext) []Finding {
	if c.Protocols == nil || c.Protocols.TLS12 != TriNo {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityHigh,
		Category: "protocol",
		Title:    "Server does not support TLS 1.2",
		Detail: "TLS 1.2 is the floor for modern clients. Servers that " +
			"only accept TLS 1.3 exclude compatibility with clients that " +
			"have not yet adopted the new version.",
		Remediation: "Enable TLS 1.2 alongside TLS 1.3 on the server.",
		Evidence:    map[string]any{"negotiated": false},
	}}
}

// ruleNoTLS13 fires when the server does not negotiate TLS 1.3.
// Low severity: TLS 1.2 remains acceptable.
type ruleNoTLS13 struct{}

func (ruleNoTLS13) ID() string { return "TLS_NO_TLS13" }

func (r ruleNoTLS13) Evaluate(c *EvalContext) []Finding {
	if c.Protocols == nil || c.Protocols.TLS13 != TriNo {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityLow,
		Category: "protocol",
		Title:    "Server does not support TLS 1.3",
		Detail: "TLS 1.3 simplifies the handshake, removes obsolete " +
			"features and provides better forward secrecy by default. " +
			"TLS 1.2 is still acceptable but the absence of 1.3 indicates " +
			"outdated server software.",
		Remediation: "Upgrade the server to a TLS 1.3-capable build.",
		Evidence:    map[string]any{"negotiated": false},
	}}
}

// ruleWeakCipher3DES fires when either the cipher-enumeration
// phase OR the raw-ClientHello phase found 3DES accepted by the
// server. The two paths cover the same finding ID because they
// answer the same question with different mechanisms: the
// crypto/tls path needs the probe to be opted in and offers a
// single 3DES suite, while the raw path offers each 3DES suite
// individually.
type ruleWeakCipher3DES struct{}

func (ruleWeakCipher3DES) ID() string { return "TLS_WEAK_CIPHER_3DES" }

func (r ruleWeakCipher3DES) Evaluate(c *EvalContext) []Finding {
	if c.Ciphers == nil && !weakCipherAccepted(c, "TLS_WEAK_CIPHER_3DES") {
		return nil
	}
	if c.Ciphers != nil && !c.Ciphers.Weak3DES && !weakCipherAccepted(c, "TLS_WEAK_CIPHER_3DES") {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityHigh,
		Category: "crypto",
		Title:    "Server accepts 3DES cipher suites",
		Detail: "3DES is vulnerable to SWEET32 (CVE-2016-2183): a " +
			"birthday-bound collision attack against the 64-bit block " +
			"size becomes practical after roughly 785 GB of traffic on " +
			"a single key.",
		Remediation: "Disable 3DES on the server. Restrict the cipher " +
			"list to AES-GCM and ChaCha20-Poly1305 suites.",
		Evidence:   map[string]any{"group": "3des"},
		References: []string{"https://sweet32.info/"},
	}}
}

// ruleWeakCipherCBCSHA1 fires when the cipher-enumeration phase
// found CBC + HMAC-SHA1 accepted.
type ruleWeakCipherCBCSHA1 struct{}

func (ruleWeakCipherCBCSHA1) ID() string { return "TLS_WEAK_CIPHER_CBC_SHA1" }

func (r ruleWeakCipherCBCSHA1) Evaluate(c *EvalContext) []Finding {
	if c.Ciphers == nil || !c.Ciphers.WeakCBCSHA1 {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityMedium,
		Category: "crypto",
		Title:    "Server accepts CBC + HMAC-SHA1 cipher suites",
		Detail: "CBC mode combined with HMAC-SHA1 is the target of " +
			"Lucky13 (timing attack against CBC padding). Modern stacks " +
			"prefer AES-GCM or ChaCha20-Poly1305 which provide AEAD.",
		Remediation: "Disable CBC + HMAC-SHA1 suites; prefer AEAD suites.",
		Evidence:    map[string]any{"group": "cbc_sha1"},
		References:  []string{"https://www.imperva.com/docs/HII_SSL_Server_BC_CBC_Cipher_Suites_Lucky13.pdf"},
	}}
}

// ruleNoForwardSecrecy fires when the cipher-enumeration phase
// could not negotiate a single ECDHE/DHE suite.
type ruleNoForwardSecrecy struct{}

func (ruleNoForwardSecrecy) ID() string { return "TLS_NO_FORWARD_SECRECY" }

func (r ruleNoForwardSecrecy) Evaluate(c *EvalContext) []Finding {
	if c.Ciphers == nil || c.Ciphers.ForwardSecrecy {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityHigh,
		Category: "crypto",
		Title:    "Server does not offer any forward-secret cipher suite",
		Detail: "Without ECDHE/DHE, a compromise of the server's long-term " +
			"private key retroactively decrypts every past session. " +
			"Forward secrecy makes this attack impractical.",
		Remediation: "Configure the server to prefer ECDHE suites " +
			"(nginx: ssl_prefer_server_ciphers on; ssl_ecdh_curve X25519:secp384r1;).",
		Evidence: map[string]any{"forward_secrecy_offered": false},
	}}
}

// ruleHSTSShortMaxAge fires when the HSTS header advertises a
// max-age below the 180-day minimum recommended by the HSTS
// preload programme.
type ruleHSTSShortMaxAge struct{}

func (ruleHSTSShortMaxAge) ID() string { return "TLS_HSTS_SHORT_MAXAGE" }

func (r ruleHSTSShortMaxAge) Evaluate(c *EvalContext) []Finding {
	if c.HSTS == nil || !c.HSTS.HSTSShortMaxAge {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityLow,
		Category: "config",
		Title:    "HSTS max-age is shorter than 180 days",
		Detail: "The Strict-Transport-Security header advertises a " +
			"max-age below the 180-day minimum recommended for the HSTS " +
			"preload list. Long max-age values harden clients against " +
			"SSL-stripping attacks.",
		Remediation: "Set max-age to at least 15552000 (180 days).",
		Evidence: map[string]any{
			"max_age":     c.HSTS.MaxAgeSeconds,
			"recommended": int64(15552000),
		},
		References: []string{"https://hstspreload.org/"},
	}}
}

// ruleHSTSOnHTTP fires when HSTS is delivered over plain HTTP.
// Strict clients ignore the header in this case but it is still
// informational for the LLM.
type ruleHSTSOnHTTP struct{}

func (ruleHSTSOnHTTP) ID() string { return "TLS_HSTS_ON_HTTP" }

func (r ruleHSTSOnHTTP) Evaluate(c *EvalContext) []Finding {
	if c.HSTS == nil || !c.HSTS.HSTSOnHTTP {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityLow,
		Category: "config",
		Title:    "Strict-Transport-Security sent over plain HTTP",
		Detail: "The HSTS header was observed on a plain HTTP response. " +
			"Per RFC 6797 §7.2, the header MUST be ignored by user agents " +
			"when delivered over insecure transport.",
		Remediation: "If the host serves both HTTP and HTTPS, ensure " +
			"HTTPS responses always include HSTS. Plain HTTP responses " +
			"should redirect to HTTPS.",
		Evidence:   map[string]any{"scheme": "http"},
		References: []string{"https://datatracker.ietf.org/doc/html/rfc6797#section-7.2"},
	}}
}

// ruleHSTSMissing fires when the HSTS phase ran and the header
// was absent. Medium severity: clients remain vulnerable to
// SSL-stripping on first contact.
type ruleHSTSMissing struct{}

func (ruleHSTSMissing) ID() string { return "TLS_HSTS_MISSING" }

func (r ruleHSTSMissing) Evaluate(c *EvalContext) []Finding {
	if c.HSTS == nil {
		return nil
	}
	if c.HSTS.StrictTransportSecurity != "" {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityMedium,
		Category: "config",
		Title:    "Strict-Transport-Security header is missing",
		Detail: "The HTTPS endpoint does not advertise an HSTS policy. " +
			"Clients are vulnerable to SSL-stripping attacks on the first " +
			"connection (no previous HSTS state to enforce).",
		Remediation: "Add a Strict-Transport-Security header with " +
			"max-age ≥ 31536000 and includeSubDomains.",
		References: []string{"https://datatracker.ietf.org/doc/html/rfc6797"},
	}}
}

// ruleHTTPNoRedirect fires when the HSTS phase ran and no HTTP→HTTPS
// redirect was observed.
type ruleHTTPNoRedirect struct{}

func (ruleHTTPNoRedirect) ID() string { return "TLS_HTTP_NO_REDIRECT" }

func (r ruleHTTPNoRedirect) Evaluate(c *EvalContext) []Finding {
	if c.HSTS == nil {
		return nil
	}
	if c.HSTS.HTTPSRedirect {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityMedium,
		Category: "config",
		Title:    "Port 80 does not redirect to HTTPS",
		Detail: "Clients that explicitly request http:// are not " +
			"redirected to the HTTPS endpoint. This forces HSTS-aware " +
			"clients to upgrade manually and gives an attacker a window " +
			"to perform SSL-stripping on the first visit.",
		Remediation: "Add a 301 redirect from http:// to https:// " +
			"on the same hostname and path.",
	}}
}

// ruleStartTLSNotOffered fires when the STARTTLS upgrade was
// requested but the server did not advertise it (the protocol
// dialogue itself failed).
type ruleStartTLSNotOffered struct{}

func (ruleStartTLSNotOffered) ID() string { return "TLS_STARTTLS_NOT_OFFERED" }

func (r ruleStartTLSNotOffered) Evaluate(c *EvalContext) []Finding {
	if c.StartTLS == nil || c.StartTLS.UpgradeSucceeded {
		return nil
	}
	// Only flag the failure when the protocol dialogue itself
	// failed; a TLS-handshake failure after a successful upgrade
	// is the subject of other rules (TLS_CERT_EXPIRED, etc.).
	if strings.Contains(c.StartTLS.FailureReason, "TLS handshake after STARTTLS") {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityMedium,
		Category: "config",
		Title:    "STARTTLS is not offered on the target port",
		Detail: "The server did not advertise STARTTLS or refused the " +
			"upgrade request. Connections on the plaintext port stay " +
			"unencrypted.",
		Remediation: "Configure the server to advertise and honour " +
			"STARTTLS upgrades.",
		Evidence: map[string]any{
			"protocol":       c.StartTLS.Protocol,
			"failure_reason": c.StartTLS.FailureReason,
		},
	}}
}

// ruleSNIDefaultMismatch fires when the no-SNI handshake returns a
// different certificate than the SNI handshake. This is a strong
// signal that the operator has not configured a strict default
// server block; legacy clients without SNI silently receive the
// wrong certificate. See PLAN.md §8.5.
type ruleSNIDefaultMismatch struct{}

func (ruleSNIDefaultMismatch) ID() string { return "TLS_SNI_DEFAULT_CERT_MISMATCH" }

func (r ruleSNIDefaultMismatch) Evaluate(c *EvalContext) []Finding {
	s := c.SNI
	if s == nil {
		// Phase was not run — no finding either way. The
		// corresponding SkippedCheck entry (in AlwaysSkipped)
		// already tells the model the check was not performed.
		return nil
	}
	if !s.NoSNIHandshakeSucceeded {
		// Strict SNI: the no-SNI handshake was refused. This is
		// actually GOOD configuration (no vhost confusion risk
		// for legacy clients) — do not flag it.
		return nil
	}
	if !s.SNIMismatch {
		return nil
	}
	severity := SeverityMedium
	if c.Leaf != nil && s.NoSNISubject != "" && c.Leaf.Subject.String() != s.NoSNISubject {
		// Mismatch AND the no-SNI certificate is for a different
		// subject — much more likely to be a real vhost leak.
		severity = SeverityHigh
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: severity,
		Category: "config",
		Title:    "Default certificate differs from the SNI-selected one",
		Detail: "Connecting without SNI yields a different certificate " +
			"(subject " + s.NoSNISubject + ") than connecting with SNI=" +
			c.Hostname + " (subject " + leafSubject(c) + "). Legacy clients " +
			"that do not emit SNI (very old Java, embedded TLS libraries, " +
			"OpenSSL s_client without -servername) will receive the wrong " +
			"certificate and fail hostname verification silently.",
		Remediation: "Configure an explicit default server with a " +
			"neutral certificate, or reject no-SNI connections altogether " +
			"(nginx: ssl_reject_handshake on in the default server block; " +
			"Apache: SSLRequireSSL with a strict default vhost).",
		Evidence: map[string]any{
			"sni_subject":        leafSubject(c),
			"no_sni_subject":     s.NoSNISubject,
			"no_sni_fingerprint": s.NoSNIFingerprint,
			"sni_fingerprint":    leafFingerprint(c.Leaf),
		},
	}}
}

// leafSubject returns the Subject.String() of the leaf, or empty
// when the leaf is nil. Small helper for the rule above.
func leafSubject(c *EvalContext) string {
	if c.Leaf == nil {
		return ""
	}
	return c.Leaf.Subject.String()
}

// leafFingerprint returns the SHA-256 fingerprint of the leaf DER,
// or empty when the leaf is nil.
func leafFingerprint(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	return fingerprintSHA256Hex(c.Raw)
}

// weakCipherAccepted reports whether the raw-ClientHello phase
// detected that the server accepted a particular weak cipher
// class. Empty when the phase did not run.
func weakCipherAccepted(c *EvalContext, id string) bool {
	for _, s := range c.WeakCiphersAccepted {
		if s == id {
			return true
		}
	}
	return false
}

// ruleWeakCipherRC4 fires when the raw-ClientHello phase observed
// the server accepting an RC4-based suite. This finding is
// undetectable with crypto/tls alone.
type ruleWeakCipherRC4 struct{}

func (ruleWeakCipherRC4) ID() string { return "TLS_WEAK_CIPHER_RC4" }

func (r ruleWeakCipherRC4) Evaluate(c *EvalContext) []Finding {
	if !weakCipherAccepted(c, "TLS_WEAK_CIPHER_RC4") {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityCritical,
		Category: "protocol",
		Title:    "Server accepts RC4 cipher suites",
		Detail: "The raw-ClientHello probe observed the server accepting " +
			"an RC4-based cipher suite (e.g. TLS_RSA_WITH_RC4_128_SHA). " +
			"RC4 has been prohibited by RFC 7465 and is exploitable in " +
			"TLS (CVE-2013-2566, NOMOREATTACKS).",
		Remediation: "Disable every RC4-based cipher suite in the server " +
			"configuration. Modern TLS clients negotiate AES-GCM or " +
			"ChaCha20-Poly1305 instead.",
	}}
}

// ruleWeakCipher3DESFromRaw has been merged into ruleWeakCipher3DES
// to keep a single source of truth for the TLS_WEAK_CIPHER_3DES
// finding ID. The merge is at the Evaluate() method of
// ruleWeakCipher3DES above.

// ruleWeakCipherNULL flags NULL cipher suites (no encryption).
type ruleWeakCipherNULL struct{}

func (ruleWeakCipherNULL) ID() string { return "TLS_WEAK_CIPHER_NULL" }

func (r ruleWeakCipherNULL) Evaluate(c *EvalContext) []Finding {
	if !weakCipherAccepted(c, "TLS_WEAK_CIPHER_NULL") {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityCritical,
		Category: "protocol",
		Title:    "Server accepts NULL cipher suites",
		Detail: "The raw-ClientHello probe observed the server accepting " +
			"a NULL cipher suite (no encryption). All traffic is in cleartext.",
		Remediation: "Remove NULL suites from the cipher list. They have " +
			"no legitimate use.",
	}}
}

// ruleWeakCipherEXPORT flags EXPORT-grade cipher suites (FREAK).
type ruleWeakCipherEXPORT struct{}

func (ruleWeakCipherEXPORT) ID() string { return "TLS_WEAK_CIPHER_EXPORT" }

func (r ruleWeakCipherEXPORT) Evaluate(c *EvalContext) []Finding {
	if !weakCipherAccepted(c, "TLS_WEAK_CIPHER_EXPORT") {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityCritical,
		Category: "protocol",
		Title:    "Server accepts EXPORT-grade cipher suites (FREAK)",
		Detail: "The raw-ClientHello probe observed the server accepting " +
			"an EXPORT cipher suite (e.g. TLS_RSA_EXPORT_WITH_RC4_40_MD5). " +
			"EXPORT suites were weakened by US export regulations and are " +
			"exploitable by FREAK (CVE-2015-0204).",
		Remediation: "Remove all EXPORT suites from the cipher list.",
	}}
}

// ruleSSLV3Enabled flags a server that still negotiates SSL 3.0.
// SSLv3 is forbidden by RFC 7568 and exploitable via POODLE
// (CVE-2014-3566). Indistinguishable from the crypto/tls version
// enumeration rule because we offer a real ClientHello at TLS 1.0
// anyway; the raw path here is the only way to test SSLv3 itself.
type ruleSSLV3Enabled struct{}

func (ruleSSLV3Enabled) ID() string { return "TLS_SSLV3_ENABLED" }

func (r ruleSSLV3Enabled) Evaluate(c *EvalContext) []Finding {
	if !weakCipherAccepted(c, "TLS_SSLV3_ENABLED") {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityCritical,
		Category: "protocol",
		Title:    "Server accepts SSL 3.0 (POODLE)",
		Detail: "The raw-ClientHello probe at SSL 3.0 received a ServerHello " +
			"at the same version, indicating the server is willing to " +
			"negotiate SSL 3.0. SSLv3 is vulnerable to POODLE " +
			"(CVE-2014-3566) and is forbidden by RFC 7568.",
		Remediation: "Disable SSL 3.0 on the server. Modern TLS clients do " +
			"not need to negotiate it.",
	}}
}
