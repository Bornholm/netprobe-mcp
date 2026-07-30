package tlsdiag

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"
)

func TestSeverity(t *testing.T) {
	cases := []struct {
		a, b Severity
		want bool
	}{
		{SeverityCritical, SeverityHigh, true},
		{SeverityHigh, SeverityHigh, true},
		{SeverityInfo, SeverityLow, false},
		{SeverityMedium, SeverityLow, true},
	}
	for _, c := range cases {
		if got := c.a.AtLeastAsSevere(c.b); got != c.want {
			t.Errorf("%s.AtLeastAsSevere(%s) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	if got := ParseSeverity("blah"); got != SeverityInfo {
		t.Errorf("ParseSeverity(blah) = %s, want info", got)
	}
	if got := ParseSeverity(string(SeverityCritical)); got != SeverityCritical {
		t.Errorf("ParseSeverity(critical) = %s", got)
	}
}

func TestFindingCounts_Add(t *testing.T) {
	var c FindingCounts
	c.Add(Finding{Severity: SeverityCritical})
	c.Add(Finding{Severity: SeverityHigh})
	c.Add(Finding{Severity: SeverityInfo})
	if c.Critical != 1 || c.High != 1 || c.Info != 1 || c.Total != 3 {
		t.Errorf("counts wrong: %+v", c)
	}
}

func TestAllSeverities_Order(t *testing.T) {
	s := AllSeverities()
	if len(s) != 5 {
		t.Fatalf("expected 5 severities, got %d", len(s))
	}
	if s[0] != SeverityCritical || s[4] != SeverityInfo {
		t.Errorf("ordering wrong: %v", s)
	}
}

func TestReport_Sanitized(t *testing.T) {
	rep := &Report{
		Leaf: CertReport{PEM: "secret"},
		Chain: ChainReport{
			PresentedCerts: []CertReport{{PEM: "a"}, {PEM: "b"}},
		},
	}
	out := rep.Sanitized()
	if out.Leaf.PEM != "" {
		t.Errorf("leaf pem not stripped")
	}
	if out.Chain.PresentedCerts[0].PEM != "" || out.Chain.PresentedCerts[1].PEM != "" {
		t.Errorf("chain pems not stripped")
	}
}

func TestAlwaysSkipped_Stable(t *testing.T) {
	s := AlwaysSkipped()
	if len(s) < 15 {
		t.Errorf("expected at least 15 skipped checks, got %d", len(s))
	}
	// IDs should be unique.
	seen := map[string]struct{}{}
	for _, e := range s {
		if _, ok := seen[e.Check]; ok {
			t.Errorf("duplicate skipped id: %s", e.Check)
		}
		seen[e.Check] = struct{}{}
	}
}

func TestFindingsFromSortedFilter(t *testing.T) {
	in := []Finding{
		{ID: "a", Severity: SeverityLow},
		{ID: "b", Severity: SeverityCritical},
		{ID: "c", Severity: SeverityMedium},
	}
	out := findingsFromSortedFilter(in, SeverityInfo)
	if len(out) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(out))
	}
	if out[0].ID != "b" {
		t.Errorf("expected critical first, got %s", out[0].ID)
	}
	out2 := findingsFromSortedFilter(in, SeverityMedium)
	if len(out2) != 2 {
		t.Fatalf("expected 2 findings after filtering, got %d", len(out2))
	}
	if out2[0].ID != "b" {
		t.Errorf("expected critical first after filter, got %s", out2[0].ID)
	}
}

// --- Validity rules ---

func TestRuleCertExpired(t *testing.T) {
	now := testClock()
	mut := func(c *x509.Certificate) {
		c.NotAfter = now.Add(-time.Hour)
	}
	leaf, _, _, _ := buildChain(t, mut)
	r := ruleCertExpired{}
	findings := r.Evaluate(&EvalContext{Now: now, Leaf: leaf, Config: defaultConfig()})
	if len(findings) != 1 || findings[0].ID != "TLS_CERT_EXPIRED" {
		t.Fatalf("expected TLS_CERT_EXPIRED, got %+v", findings)
	}
}

func TestRuleCertNotYetValid(t *testing.T) {
	now := testClock()
	mut := func(c *x509.Certificate) {
		c.NotBefore = now.Add(time.Hour)
	}
	leaf, _, _, _ := buildChain(t, mut)
	findings := ruleCertNotYetValid{}.Evaluate(&EvalContext{Now: now, Leaf: leaf, Config: defaultConfig()})
	if len(findings) != 1 || findings[0].ID != "TLS_CERT_NOT_YET_VALID" {
		t.Fatalf("expected TLS_CERT_NOT_YET_VALID, got %+v", findings)
	}
}

func TestRuleCertExpiringCritical(t *testing.T) {
	now := testClock()
	mut := func(c *x509.Certificate) {
		c.NotAfter = now.Add(3 * 24 * time.Hour)
	}
	leaf, _, _, _ := buildChain(t, mut)
	findings := ruleCertExpiringCritical{}.Evaluate(&EvalContext{Now: now, Leaf: leaf, Config: defaultConfig()})
	if len(findings) != 1 || findings[0].ID != "TLS_CERT_EXPIRING_CRITICAL" {
		t.Fatalf("expected TLS_CERT_EXPIRING_CRITICAL, got %+v", findings)
	}
}

func TestRuleCertExpiringSoon(t *testing.T) {
	now := testClock()
	mut := func(c *x509.Certificate) {
		c.NotAfter = now.Add(15 * 24 * time.Hour)
	}
	leaf, _, _, _ := buildChain(t, mut)
	findings := ruleCertExpiringSoon{}.Evaluate(&EvalContext{Now: now, Leaf: leaf, Config: defaultConfig()})
	if len(findings) != 1 || findings[0].ID != "TLS_CERT_EXPIRING_SOON" {
		t.Fatalf("expected TLS_CERT_EXPIRING_SOON, got %+v", findings)
	}
}

func TestRuleCertExpiringSoon_NotTriggered(t *testing.T) {
	now := testClock()
	mut := func(c *x509.Certificate) {
		c.NotAfter = now.Add(60 * 24 * time.Hour)
	}
	leaf, _, _, _ := buildChain(t, mut)
	findings := ruleCertExpiringSoon{}.Evaluate(&EvalContext{Now: now, Leaf: leaf, Config: defaultConfig()})
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
}

func TestRuleValidityTooLong(t *testing.T) {
	now := testClock()
	mut := func(c *x509.Certificate) {
		c.NotAfter = now.Add(500 * 24 * time.Hour) // 500 days
	}
	leaf, _, _, _ := buildChain(t, mut)
	findings := ruleValidityTooLong{}.Evaluate(&EvalContext{Now: now, Leaf: leaf, Config: defaultConfig()})
	if len(findings) != 1 || findings[0].ID != "TLS_VALIDITY_TOO_LONG" {
		t.Fatalf("expected TLS_VALIDITY_TOO_LONG, got %+v", findings)
	}
}

func TestRuleValidityExcessive(t *testing.T) {
	now := testClock()
	mut := func(c *x509.Certificate) {
		c.NotAfter = now.Add(900 * 24 * time.Hour) // 900 days
	}
	leaf, _, _, _ := buildChain(t, mut)
	findings := ruleValidityExcessive{}.Evaluate(&EvalContext{Now: now, Leaf: leaf, Config: defaultConfig()})
	if len(findings) != 1 || findings[0].ID != "TLS_VALIDITY_EXCESSIVE" {
		t.Fatalf("expected TLS_VALIDITY_EXCESSIVE, got %+v", findings)
	}
}

// --- Identity rules ---

func TestRuleHostnameMismatch(t *testing.T) {
	leaf, _, _, _ := buildChain(t, nil)
	findings := ruleHostnameMismatch{}.Evaluate(&EvalContext{Now: testClock(), Leaf: leaf, Hostname: "evil.example.org", Config: defaultConfig()})
	if len(findings) != 1 || findings[0].ID != "TLS_HOSTNAME_MISMATCH" {
		t.Fatalf("expected TLS_HOSTNAME_MISMATCH, got %+v", findings)
	}
}

func TestRuleNoSAN(t *testing.T) {
	mut := func(c *x509.Certificate) {
		c.DNSNames = nil
		c.IPAddresses = nil
		c.URIs = nil
		c.EmailAddresses = nil
	}
	leaf, _, _, _ := buildChain(t, mut)
	findings := ruleNoSAN{}.Evaluate(&EvalContext{Now: testClock(), Leaf: leaf, Config: defaultConfig()})
	if len(findings) != 1 || findings[0].ID != "TLS_NO_SAN" {
		t.Fatalf("expected TLS_NO_SAN, got %+v", findings)
	}
}

func TestRuleCNOnlyIdentity(t *testing.T) {
	mut := func(c *x509.Certificate) {
		c.DNSNames = nil
		c.IPAddresses = nil
		c.Subject.CommonName = "fallback.example.com"
	}
	leaf, _, _, _ := buildChain(t, mut)
	findings := ruleCNOnlyIdentity{}.Evaluate(&EvalContext{Now: testClock(), Leaf: leaf, Config: defaultConfig()})
	if len(findings) != 1 || findings[0].ID != "TLS_CN_ONLY_IDENTITY" {
		t.Fatalf("expected TLS_CN_ONLY_IDENTITY, got %+v", findings)
	}
}

func TestRuleWildcardScope_PublicSuffix(t *testing.T) {
	mut := func(c *x509.Certificate) {
		c.DNSNames = []string{"*.com"}
	}
	leaf, _, _, _ := buildChain(t, mut)
	findings := ruleWildcardScope{}.Evaluate(&EvalContext{Now: testClock(), Leaf: leaf, Config: defaultConfig()})
	if len(findings) != 1 || findings[0].ID != "TLS_WILDCARD_TOO_BROAD" {
		t.Fatalf("expected TLS_WILDCARD_TOO_BROAD, got %+v", findings)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("expected high severity, got %s", findings[0].Severity)
	}
}

func TestRuleWildcardScope_BroadDomain(t *testing.T) {
	mut := func(c *x509.Certificate) {
		c.DNSNames = []string{"*.example.com"}
	}
	leaf, _, _, _ := buildChain(t, mut)
	findings := ruleWildcardScope{}.Evaluate(&EvalContext{Now: testClock(), Leaf: leaf, Config: defaultConfig()})
	if len(findings) != 1 || findings[0].ID != "TLS_WILDCARD_TOO_BROAD" {
		t.Fatalf("expected TLS_WILDCARD_TOO_BROAD, got %+v", findings)
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("expected medium severity, got %s", findings[0].Severity)
	}
}

// --- Crypto rules ---

func TestRuleWeakRSAKey(t *testing.T) {
	now := testClock()
	mut := func(c *x509.Certificate) {
		c.NotBefore = now.Add(-time.Hour)
		c.NotAfter = now.Add(90 * 24 * time.Hour)
	}
	leaf, _, _, _ := buildChainWithRSA(t, 1024, mut)
	findings := ruleWeakRSAKey{}.Evaluate(&EvalContext{Now: now, Leaf: leaf, Config: defaultConfig()})
	if len(findings) != 1 || findings[0].ID != "TLS_WEAK_RSA_KEY" {
		t.Fatalf("expected TLS_WEAK_RSA_KEY, got %+v", findings)
	}
}

func TestRuleSuboptimalRSAKey(t *testing.T) {
	now := testClock()
	mut := func(c *x509.Certificate) {
		c.NotBefore = now.Add(-time.Hour)
		c.NotAfter = now.Add(90 * 24 * time.Hour)
	}
	leaf, _, _, _ := buildChainWithRSA(t, 2048, mut)
	findings := ruleSuboptimalRSAKey{}.Evaluate(&EvalContext{Now: now, Leaf: leaf, Config: defaultConfig()})
	if len(findings) != 1 || findings[0].ID != "TLS_SUBOPTIMAL_RSA_KEY" {
		t.Fatalf("expected TLS_SUBOPTIMAL_RSA_KEY, got %+v", findings)
	}
}

func TestRuleWeakECCurve(t *testing.T) {
	mut := func(c *x509.Certificate) {
		c.DNSNames = []string{"leaf.example.com"}
	}
	leaf, _, _, _ := buildChainWithP224(t, mut)
	findings := ruleWeakECCurve{}.Evaluate(&EvalContext{Now: testClock(), Leaf: leaf, Config: defaultConfig()})
	if len(findings) != 1 || findings[0].ID != "TLS_WEAK_EC_CURVE" {
		t.Fatalf("expected TLS_WEAK_EC_CURVE, got %+v", findings)
	}
}

func TestRuleCACertUsedAsLeaf(t *testing.T) {
	mut := func(c *x509.Certificate) {
		c.IsCA = true
	}
	leaf, _, _, _ := buildChain(t, mut)
	findings := ruleCACertUsedAsLeaf{}.Evaluate(&EvalContext{Now: testClock(), Leaf: leaf, Config: defaultConfig()})
	if len(findings) != 1 || findings[0].ID != "TLS_CA_CERT_USED_AS_LEAF" {
		t.Fatalf("expected TLS_CA_CERT_USED_AS_LEAF, got %+v", findings)
	}
}

// --- Config rules ---

func TestRuleKeyUsageMissing(t *testing.T) {
	mut := func(c *x509.Certificate) {
		c.KeyUsage = 0
	}
	leaf, _, _, _ := buildChain(t, mut)
	findings := ruleKeyUsageMissing{}.Evaluate(&EvalContext{Now: testClock(), Leaf: leaf, Config: defaultConfig()})
	if len(findings) != 1 || findings[0].ID != "TLS_KEY_USAGE_MISSING" {
		t.Fatalf("expected TLS_KEY_USAGE_MISSING, got %+v", findings)
	}
}

func TestRuleKeyUsageNoDigitalSignature(t *testing.T) {
	mut := func(c *x509.Certificate) {
		c.KeyUsage = x509.KeyUsageKeyEncipherment
	}
	leaf, _, _, _ := buildChain(t, mut)
	findings := ruleKeyUsageNoDigitalSignature{}.Evaluate(&EvalContext{Now: testClock(), Leaf: leaf, Config: defaultConfig()})
	if len(findings) != 1 || findings[0].ID != "TLS_KEY_USAGE_NO_DIGSIG" {
		t.Fatalf("expected TLS_KEY_USAGE_NO_DIGSIG, got %+v", findings)
	}
}

func TestRuleEKUMissingServerAuth(t *testing.T) {
	mut := func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	leaf, _, _, _ := buildChain(t, mut)
	findings := ruleEKUMissingServerAuth{}.Evaluate(&EvalContext{Now: testClock(), Leaf: leaf, Config: defaultConfig()})
	if len(findings) != 1 || findings[0].ID != "TLS_EKU_MISSING_SERVER_AUTH" {
		t.Fatalf("expected TLS_EKU_MISSING_SERVER_AUTH, got %+v", findings)
	}
}

func TestRuleEKUOverlyBroad(t *testing.T) {
	mut := func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	leaf, _, _, _ := buildChain(t, mut)
	findings := ruleEKUOverlyBroad{}.Evaluate(&EvalContext{Now: testClock(), Leaf: leaf, Config: defaultConfig()})
	if len(findings) != 1 || findings[0].ID != "TLS_EKU_OVERLY_BROAD" {
		t.Fatalf("expected TLS_EKU_OVERLY_BROAD, got %+v", findings)
	}
}

func TestRuleMustStapleWithoutStaple(t *testing.T) {
	mut := func(c *x509.Certificate) {
		c.ExtraExtensions = []pkix.Extension{{
			Id:    mustStapleOID(),
			Value: encodeMustStaple(),
		}}
	}
	leaf, _, _, _ := buildChain(t, mut)
	findings := ruleMustStapleWithoutStaple{}.Evaluate(&EvalContext{
		Now:    testClock(),
		Leaf:   leaf,
		OCSP:   nil, // no staple
		Config: defaultConfig(),
	})
	if len(findings) != 1 || findings[0].ID != "TLS_MUST_STAPLE_WITHOUT_STAPLE" {
		t.Fatalf("expected TLS_MUST_STAPLE_WITHOUT_STAPLE, got %+v", findings)
	}
}

func TestRuleMustStapleWithStaple(t *testing.T) {
	mut := func(c *x509.Certificate) {
		c.ExtraExtensions = []pkix.Extension{{
			Id:    mustStapleOID(),
			Value: encodeMustStaple(),
		}}
	}
	leaf, _, _, _ := buildChain(t, mut)
	findings := ruleMustStapleWithoutStaple{}.Evaluate(&EvalContext{
		Now:    testClock(),
		Leaf:   leaf,
		OCSP:   &OCSPReport{Stapled: true, StapleStatus: "good"},
		Config: defaultConfig(),
	})
	if len(findings) != 0 {
		t.Fatalf("expected no findings with staple, got %+v", findings)
	}
}

func TestRuleOCSPStapleExpired(t *testing.T) {
	now := testClock()
	next := now.Add(-time.Hour)
	findings := ruleOCSPStapleExpired{}.Evaluate(&EvalContext{
		Now:    now,
		OCSP:   &OCSPReport{Stapled: true, StapleExpired: true, StapleNextUpdate: &next},
		Config: defaultConfig(),
	})
	if len(findings) != 1 || findings[0].ID != "TLS_OCSP_STAPLE_EXPIRED" {
		t.Fatalf("expected TLS_OCSP_STAPLE_EXPIRED, got %+v", findings)
	}
}

func TestRuleOCSPStapleStale(t *testing.T) {
	now := testClock()
	findings := ruleOCSPStapleStale{}.Evaluate(&EvalContext{
		Now:    now,
		OCSP:   &OCSPReport{Stapled: true, StapleAgeHours: 100},
		Config: defaultConfig(),
	})
	if len(findings) != 1 || findings[0].ID != "TLS_OCSP_STAPLE_STALE" {
		t.Fatalf("expected TLS_OCSP_STAPLE_STALE, got %+v", findings)
	}
}

func TestRuleOCSPStapleInvalidSig(t *testing.T) {
	findings := ruleOCSPStapleInvalidSig{}.Evaluate(&EvalContext{
		Now:    testClock(),
		OCSP:   &OCSPReport{Stapled: true, StapleSigValid: ptr(false)},
		Config: defaultConfig(),
	})
	if len(findings) != 1 || findings[0].ID != "TLS_OCSP_STAPLE_INVALID_SIG" {
		t.Fatalf("expected TLS_OCSP_STAPLE_INVALID_SIG, got %+v", findings)
	}
}

func TestRuleCertRevoked(t *testing.T) {
	revokedAt := testClock()
	findings := ruleCertRevoked{}.Evaluate(&EvalContext{
		Now:    testClock(),
		OCSP:   &OCSPReport{Stapled: true, StapleStatus: "revoked", RevokedAt: &revokedAt, RevocationReason: "key_compromise"},
		Config: defaultConfig(),
	})
	if len(findings) != 1 || findings[0].ID != "TLS_CERT_REVOKED" {
		t.Fatalf("expected TLS_CERT_REVOKED, got %+v", findings)
	}
}

// --- Consistency rules ---

func TestRuleLeafNotFirst(t *testing.T) {
	mut := func(c *x509.Certificate) {
		c.DNSNames = nil
		c.IPAddresses = nil
		c.URIs = nil
		c.EmailAddresses = nil
	}
	leaf, inter, _, _ := buildChain(t, mut)
	findings := ruleLeafNotFirst{}.Evaluate(&EvalContext{
		Now:    testClock(),
		Leaf:   leaf,
		Chain:  []*x509.Certificate{leaf, inter},
		Config: defaultConfig(),
	})
	if len(findings) != 1 || findings[0].ID != "TLS_LEAF_NOT_FIRST" {
		t.Fatalf("expected TLS_LEAF_NOT_FIRST, got %+v", findings)
	}
}

func TestRuleDuplicateCertInChain(t *testing.T) {
	leaf, inter, _, _ := buildChain(t, nil)
	findings := ruleDuplicateCertInChain{}.Evaluate(&EvalContext{
		Now:    testClock(),
		Leaf:   leaf,
		Chain:  []*x509.Certificate{leaf, inter, leaf},
		Config: defaultConfig(),
	})
	if len(findings) != 1 || findings[0].ID != "TLS_DUPLICATE_CERT_IN_CHAIN" {
		t.Fatalf("expected TLS_DUPLICATE_CERT_IN_CHAIN, got %+v", findings)
	}
}

// --- helpers ---

func defaultConfig() Config {
	return Config{
		ExpiringSoonDays:      30,
		ExpiringCriticalDays:  7,
		MaxValidityDays:       398,
		ExcessiveValidityDays: 825,
		MinRSAKeyBits:         2048,
		MinECKeyBits:          256,
	}
}

func mustStapleOID() asn1.ObjectIdentifier {
	// 1.3.6.1.5.5.7.1.24 (id-pe-tlsfeature)
	return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
}
