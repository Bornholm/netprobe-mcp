package tlsdiag

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// describeCert returns a structured view of a single certificate. The
// optional includePEM flag controls whether the PEM-encoded body is
// included; the MCP layer also enforces this independently, but the
// analyser honours it as a second line of defence.
func describeCert(cert *x509.Certificate, hostname string, now time.Time, includePEM bool) CertReport {
	rep := CertReport{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       formatSerial(cert.SerialNumber),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		DaysUntilExpiry:    daysUntil(now, cert.NotAfter),
		ValidityDays:       cert.NotAfter.Sub(cert.NotBefore).Hours() / 24,
		Expired:            now.After(cert.NotAfter),
		NotYetValid:        now.Before(cert.NotBefore),
		SelfSigned:         isSelfSigned(cert),
		IsCA:               cert.IsCA,
		DNSNames:           append([]string{}, cert.DNSNames...),
		EmailAddresses:     append([]string{}, cert.EmailAddresses...),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		OCSPServers:        append([]string{}, cert.OCSPServer...),
		IssuingCertURLs:    append([]string{}, cert.IssuingCertificateURL...),
		CRLDistPoints:      append([]string{}, cert.CRLDistributionPoints...),
		MustStaple:         hasMustStapleExtension(cert),
		SubjectKeyID:       hex.EncodeToString(cert.SubjectKeyId),
		AuthorityKeyID:     hex.EncodeToString(cert.AuthorityKeyId),
		FingerprintSHA256:  fingerprintSHA256(cert.Raw),
		SPKISHA256:         spkiSHA256(cert),
		KeyUsage:           decodeKeyUsage(cert.KeyUsage),
		ExtKeyUsage:        decodeExtKeyUsage(cert.ExtKeyUsage),
	}
	for _, ip := range cert.IPAddresses {
		rep.IPAddresses = append(rep.IPAddresses, ip.String())
	}
	for _, u := range cert.URIs {
		rep.URIs = append(rep.URIs, u.String())
	}
	rep.PublicKeyAlgorithm, rep.PublicKeyBits, rep.PublicKeyCurve = describePublicKey(cert.PublicKey)

	if includePEM {
		rep.PEM = encodePEM(cert.Raw)
	}
	_ = hostname // reserved for future "matched name" annotation; the
	//            hostname match is computed in chain.go on the leaf.
	return rep
}

// formatSerial prints the certificate serial number with leading zeroes
// stripped, matching common UI conventions while preserving a
// hex-fallback for negative serials (rare but legal in X.509).
func formatSerial(s *big.Int) string {
	if s == nil {
		return ""
	}
	if s.Sign() < 0 {
		return "-" + new(big.Int).Abs(s).Text(16)
	}
	return s.String()
}

// fingerprintSHA256 returns the lowercase hex SHA-256 of the DER cert.
func fingerprintSHA256(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// spkiSHA256 returns the base64-encoded SHA-256 of the SubjectPublicKeyInfo.
// This is the same format used for HPKP pins and OCSP responder cert
// identifiers.
func spkiSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// hasMustStapleExtension returns true when the certificate carries the
// TLS Feature extension (OID 1.3.6.1.5.5.7.1.24) with the
// status_request feature. Go's x509 parser does not surface this
// extension by name, so we walk ExtraExtensions.
func hasMustStapleExtension(cert *x509.Certificate) bool {
	const tlsFeatureOID = "1.3.6.1.5.5.7.1.24"
	for _, ext := range cert.Extensions {
		if ext.Id.String() != tlsFeatureOID {
			continue
		}
		// RFC 7633 §4.2: the value is a DER-encoded SEQUENCE OF INTEGER.
		// status_request has the value 5.
		for _, f := range decodeTLSFeatures(ext.Value) {
			if f == 5 {
				return true
			}
		}
	}
	return false
}

// decodeTLSFeatures decodes the SEQUENCE OF INTEGER pattern defined by
// RFC 7633. It returns an empty slice on any error rather than panicking
// — a malformed TLS Feature extension is not a finding on its own.
func decodeTLSFeatures(raw []byte) []int {
	var out []int
	rest := raw
	for len(rest) > 0 {
		// SEQUENCE tag = 0x30, INTEGER tag = 0x02.
		if rest[0] != 0x30 {
			break
		}
		seqLen, consumed, after := parseDERLen(rest[1:])
		if consumed == 0 {
			break
		}
		// Move past SEQUENCE tag + length bytes + content.
		rest = after[:seqLen]
		for len(rest) > 0 {
			if rest[0] != 0x02 {
				break
			}
			intLen, consumed2, after2 := parseDERLen(rest[1:])
			if consumed2 == 0 {
				return out
			}
			rest = after2[:intLen]
			val := 0
			for _, b := range rest {
				val = val<<8 | int(b)
			}
			out = append(out, val)
			rest = after2[intLen:]
		}
		// Advance past the sequence.
		if len(after) < seqLen {
			return out
		}
		rest = after[seqLen:]
	}
	return out
}

// parseDERLen parses a single DER length field, returning the length
// value, the number of bytes consumed (for the multi-byte form), and
// the remaining bytes.
func parseDERLen(b []byte) (int, int, []byte) {
	if len(b) == 0 {
		return 0, 0, nil
	}
	first := int(b[0])
	if first < 0x80 {
		return first, 1, b[1:]
	}
	n := first & 0x7f
	if n == 0 || n > len(b)-1 {
		return 0, 0, nil
	}
	v := 0
	for i := 0; i < n; i++ {
		v = v<<8 | int(b[1+i])
	}
	return v, 1 + n, b[1+n:]
}

// decodeKeyUsage converts the bitmask into a stable string list so
// findings can compare against expected values across runs.
func decodeKeyUsage(ku x509.KeyUsage) []string {
	all := []struct {
		bit x509.KeyUsage
		s   string
	}{
		{x509.KeyUsageDigitalSignature, "digital_signature"},
		{x509.KeyUsageContentCommitment, "content_commitment"},
		{x509.KeyUsageKeyEncipherment, "key_encipherment"},
		{x509.KeyUsageDataEncipherment, "data_encipherment"},
		{x509.KeyUsageKeyAgreement, "key_agreement"},
		{x509.KeyUsageCertSign, "cert_sign"},
		{x509.KeyUsageCRLSign, "crl_sign"},
		{x509.KeyUsageEncipherOnly, "encipher_only"},
		{x509.KeyUsageDecipherOnly, "decipher_only"},
	}
	var out []string
	for _, e := range all {
		if ku&e.bit != 0 {
			out = append(out, e.s)
		}
	}
	return out
}

// decodeExtKeyUsage returns the EKU list with stable names that match
// rule evidence lookups.
func decodeExtKeyUsage(eku []x509.ExtKeyUsage) []string {
	if len(eku) == 0 {
		return nil
	}
	out := make([]string, 0, len(eku))
	for _, e := range eku {
		switch e {
		case x509.ExtKeyUsageServerAuth:
			out = append(out, "server_auth")
		case x509.ExtKeyUsageClientAuth:
			out = append(out, "client_auth")
		case x509.ExtKeyUsageCodeSigning:
			out = append(out, "code_signing")
		case x509.ExtKeyUsageEmailProtection:
			out = append(out, "email_protection")
		case x509.ExtKeyUsageTimeStamping:
			out = append(out, "time_stamping")
		case x509.ExtKeyUsageOCSPSigning:
			out = append(out, "ocsp_signing")
		case x509.ExtKeyUsageAny:
			out = append(out, "any")
		default:
			out = append(out, fmt.Sprintf("ext_key_usage(%d)", int(e)))
		}
	}
	return out
}

// describePublicKey returns a triple (algorithm, bits, curve) suitable
// for direct inclusion in a CertReport.
func describePublicKey(pub any) (string, int, string) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen(), ""
	case *ecdsa.PublicKey:
		curve := k.Curve.Params().Name
		return "ECDSA", k.Curve.Params().BitSize, curve
	default:
		return fmt.Sprintf("%T", pub), 0, ""
	}
}

func encodePEM(der []byte) string {
	const blockType = "CERTIFICATE"
	encoded := base64.StdEncoding.EncodeToString(der)
	var b strings.Builder
	b.WriteString("-----BEGIN ")
	b.WriteString(blockType)
	b.WriteString("-----\n")
	for i := 0; i < len(encoded); i += 64 {
		end := i + 64
		if end > len(encoded) {
			end = len(encoded)
		}
		b.WriteString(encoded[i:end])
		b.WriteByte('\n')
	}
	b.WriteString("-----END ")
	b.WriteString(blockType)
	b.WriteString("-----\n")
	return b.String()
}

// hostnameMatches reports whether the leaf cert's identity matches the
// given hostname. IP literals are compared via SAN IP entries; DNS
// names via SAN DNS entries (wildcards handled). CommonName is used as
// a fallback only when SAN is absent, in line with modern CA policy.
func hostnameMatches(cert *x509.Certificate, hostname string) (bool, string) {
	if hostname == "" {
		return false, ""
	}
	if addr, err := netip.ParseAddr(hostname); err == nil {
		for _, ip := range cert.IPAddresses {
			if addr == netip.MustParseAddr(ip.String()) {
				return true, ip.String()
			}
		}
		return false, ""
	}
	h := strings.ToLower(hostname)
	if len(cert.DNSNames) > 0 {
		for _, name := range cert.DNSNames {
			if matchHost(h, strings.ToLower(name)) {
				return true, name
			}
		}
		return false, ""
	}
	// CN fallback: only used when SAN is missing, which is itself a
	// finding (TLS_NO_SAN / TLS_CN_ONLY_IDENTITY).
	for _, uri := range cert.URIs {
		if u, err := url.Parse(uri.String()); err == nil && matchHost(h, strings.ToLower(u.Host)) {
			return true, u.Host
		}
	}
	if matchHost(h, strings.ToLower(cert.Subject.CommonName)) {
		return true, cert.Subject.CommonName
	}
	return false, ""
}

// matchHost implements wildcard matching following RFC 6125 §6.4.3
// (single wildcard label, only in the left-most position).
func matchHost(host, pattern string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return host == pattern
	}
	suffix := pattern[2:]
	if !strings.HasSuffix(host, "."+suffix) {
		return false
	}
	left := strings.TrimSuffix(host, "."+suffix)
	if left == "" || strings.Contains(left, ".") {
		return false
	}
	return true
}

// isSelfSigned returns true when subject == issuer. It does not
// validate the signature — chain verification is responsible for
// that. This is a coarse, side-effect-free heuristic.
func isSelfSigned(cert *x509.Certificate) bool {
	return cert != nil && cert.RawIssuer != nil && bytesEqual(cert.RawIssuer, cert.RawSubject)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// daysUntil returns the number of full days between now and future. A
// negative value means future is in the past (i.e. the certificate is
// expired or not yet valid).
func daysUntil(now, future time.Time) float64 {
	return future.Sub(now).Hours() / 24
}

// isChainOrdered checks that each cert in the chain is issued by the
// next one (issuer == subject). Does not verify signatures.
func isChainOrdered(certs []*x509.Certificate) bool {
	for i := 0; i < len(certs)-1; i++ {
		if certs[i] == nil || certs[i+1] == nil {
			return false
		}
		if !bytesEqual(certs[i].RawIssuer, certs[i+1].RawSubject) {
			return false
		}
	}
	return true
}

// findExtraneous returns subjects of any certificate that cannot be
// linked into the leaf → root chain.
func findExtraneous(certs []*x509.Certificate) []string {
	if len(certs) < 2 {
		return nil
	}
	linked := make(map[string]struct{}, len(certs)*2)
	linked[string(certs[0].RawSubject)] = struct{}{}
	for i := 0; i < len(certs)-1; i++ {
		linked[string(certs[i+1].RawSubject)] = struct{}{}
	}
	var extra []string
	for _, c := range certs {
		if _, ok := linked[string(c.RawSubject)]; !ok {
			extra = append(extra, c.Subject.String())
		}
	}
	if len(extra) == 0 {
		return nil
	}
	return extra
}
