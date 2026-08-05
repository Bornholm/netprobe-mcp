package tlsdiag

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"strings"
)

// ruleWeakSignature flags certificates signed with SHA-1, MD5 or MD2.
// Critical because these signatures are forgeable in practice.
type ruleWeakSignature struct{ ruleSpec }

func newRuleWeakSignature() ruleWeakSignature {
	return ruleWeakSignature{ruleSpec{
		id:          "TLS_WEAK_SIGNATURE_SHA1",
		severity:    SeverityCritical,
		category:    "crypto",
		title:       "Certificate uses a weak signature algorithm",
		remediation: "Reissue the certificate with at least SHA-256 (RSA-SHA256, ECDSA-with-SHA256, or RSA-PSS). ACME clients default to SHA-256; the weak algorithm indicates a manual or legacy issuance pipeline.",
	}}
}

func (r ruleWeakSignature) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil {
		return nil
	}
	algo := strings.ToLower(c.Leaf.SignatureAlgorithm.String())
	switch {
	case strings.Contains(algo, "sha1") || strings.Contains(algo, "sha-1"):
		return []Finding{weakSigFinding(r.ID(), "SHA-1", algo, c.Leaf)}
	case strings.Contains(algo, "md5"):
		return []Finding{weakSigFinding(r.ID(), "MD5", algo, c.Leaf)}
	case strings.Contains(algo, "md2"):
		return []Finding{weakSigFinding(r.ID(), "MD2", algo, c.Leaf)}
	}
	return nil
}

func weakSigFinding(id, label, algo string, cert *x509.Certificate) Finding {
	return Finding{
		ID:       id,
		Severity: SeverityCritical,
		Category: "crypto",
		Title:    "Certificate uses a weak signature algorithm (" + label + ")",
		Detail:   "The leaf certificate is signed with " + label + ", which is considered cryptographically broken and trivially forgeable.",
		Remediation: "Reissue the certificate with at least SHA-256 (RSA-SHA256, " +
			"ECDSA-with-SHA256, or RSA-PSS). ACME clients default to SHA-256; the " +
			"weak algorithm indicates a manual or legacy issuance pipeline.",
		Evidence: map[string]any{
			"signature_algorithm": algo,
			"fingerprint_sha256":  fingerprintSHA256(cert.Raw),
		},
		References: []string{"https://www.schneier.com/blog/archives/2005/02/sha1_broken.html"},
	}
}

// ruleWeakRSAKey flags RSA keys below the configured threshold.
type ruleWeakRSAKey struct{ ruleSpec }

func newRuleWeakRSAKey() ruleWeakRSAKey {
	return ruleWeakRSAKey{ruleSpec{
		id:          "TLS_WEAK_RSA_KEY",
		severity:    SeverityCritical,
		category:    "crypto",
		title:       "RSA key is too short",
		remediation: "Reissue with at least the configured minimum (2048 bits by default). New issuance should default to 3072 or 4096 bits, or migrate to ECDSA P-256/P-384.",
	}}
}

func (r ruleWeakRSAKey) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil {
		return nil
	}
	rsaKey, ok := c.Leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil
	}
	if rsaKey.N.BitLen() >= c.Config.MinRSAKeyBits {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityCritical,
		Category: "crypto",
		Title:    "RSA key is too short",
		Detail:   "The leaf certificate's RSA modulus is below the configured minimum. Short RSA keys are within reach of nation-state adversaries and large cloud operators.",
		Remediation: "Reissue with at least " + itoa(c.Config.MinRSAKeyBits) +
			" bits. New issuance should default to 3072 or 4096 bits, or migrate to ECDSA P-256/P-384.",
		Evidence: map[string]any{
			"public_key_bits":  rsaKey.N.BitLen(),
			"min_rsa_key_bits": c.Config.MinRSAKeyBits,
		},
	}}
}

// ruleSuboptimalRSAKey flags RSA keys that are exactly at the minimum
// (2048 by default). Low severity — acceptable today but underprefers
// ECDSA and longer keys.
type ruleSuboptimalRSAKey struct{ ruleSpec }

func newRuleSuboptimalRSAKey() ruleSuboptimalRSAKey {
	return ruleSuboptimalRSAKey{ruleSpec{
		id:          "TLS_SUBOPTIMAL_RSA_KEY",
		severity:    SeverityLow,
		category:    "crypto",
		title:       "RSA key is at the minimum recommended size",
		remediation: "Consider migrating to ECDSA P-256 or to RSA-3072. ECDSA P-256 is widely supported by modern browsers and libraries.",
	}}
}

func (r ruleSuboptimalRSAKey) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil {
		return nil
	}
	rsaKey, ok := c.Leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil
	}
	if rsaKey.N.BitLen() != c.Config.MinRSAKeyBits {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityLow,
		Category: "crypto",
		Title:    "RSA key is at the minimum recommended size",
		Detail:   "The leaf certificate's RSA modulus equals the configured minimum (2048 bits by default). This is acceptable today but encourages moving to ECDSA P-256 (smaller, faster) or to 3072+ bit RSA for longevity.",
		Remediation: "Consider migrating to ECDSA P-256 or to RSA-3072. ECDSA P-256 " +
			"is widely supported by modern browsers and libraries.",
		Evidence: map[string]any{
			"public_key_bits": rsaKey.N.BitLen(),
		},
	}}
}

// ruleWeakECCurve flags ECDSA keys on curves below the configured
// minimum (P-224 or smaller).
type ruleWeakECCurve struct{ ruleSpec }

func newRuleWeakECCurve() ruleWeakECCurve {
	return ruleWeakECCurve{ruleSpec{
		id:          "TLS_WEAK_EC_CURVE",
		severity:    SeverityHigh,
		category:    "crypto",
		title:       "ECDSA key uses a weak curve",
		remediation: "Reissue with ECDSA P-256 or P-384. Avoid custom curves; NIST P-256/P-384 are widely supported.",
	}}
}

func (r ruleWeakECCurve) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil {
		return nil
	}
	ecKey, ok := c.Leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil
	}
	bits := ecKey.Curve.Params().BitSize
	if bits >= c.Config.MinECKeyBits {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityHigh,
		Category: "crypto",
		Title:    "ECDSA key uses a weak curve",
		Detail: "The leaf certificate's ECDSA curve has fewer than " + itoa(c.Config.MinECKeyBits) +
			" bits. NIST P-224 (and below) are not recommended for TLS.",
		Remediation: "Reissue with ECDSA P-256 or P-384. Avoid custom curves; " +
			"NIST P-256/P-384 are widely supported.",
		Evidence: map[string]any{
			"curve":           ecKey.Curve.Params().Name,
			"public_key_bits": bits,
			"min_ec_key_bits": c.Config.MinECKeyBits,
		},
	}}
}

// ruleCACertUsedAsLeaf flags leaf certificates with the CA basic
// constraint set. High severity: this is a configuration mistake that
// some clients reject outright.
type ruleCACertUsedAsLeaf struct{ ruleSpec }

func newRuleCACertUsedAsLeaf() ruleCACertUsedAsLeaf {
	return ruleCACertUsedAsLeaf{ruleSpec{
		id:          "TLS_CA_CERT_USED_AS_LEAF",
		severity:    SeverityHigh,
		category:    "crypto",
		title:       "Certificate has the CA basic constraint but is served as a leaf",
		remediation: "Reissue the leaf without the CA basic constraint. The CA certificate and the leaf certificate should be distinct.",
	}}
}

func (r ruleCACertUsedAsLeaf) Evaluate(c *EvalContext) []Finding {
	if c.Leaf == nil || !c.Leaf.IsCA {
		return nil
	}
	return []Finding{{
		ID:       r.ID(),
		Severity: SeverityHigh,
		Category: "crypto",
		Title:    "Certificate has the CA basic constraint but is served as a leaf",
		Detail:   "The leaf certificate carries the CA basic constraint. Some clients (notably strict TLS implementations) reject such certificates when used as a leaf.",
		Remediation: "Reissue the leaf without the CA basic constraint. The CA " +
			"certificate and the leaf certificate should be distinct.",
		Evidence: map[string]any{
			"subject": c.Leaf.Subject.String(),
		},
	}}
}
