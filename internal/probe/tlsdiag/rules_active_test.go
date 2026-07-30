// Tests for the rules introduced by the active phases.

package tlsdiag

import (
	"testing"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

func ptrBool(v bool) *bool { return &v }

func TestRuleTLS10Enabled(t *testing.T) {
	rep := &Report{}
	r := ruleTLS10Enabled{}
	if got := r.Evaluate(&EvalContext{Protocols: &ProtocolSupport{TLS10: TriYes}}); len(got) != 1 {
		t.Errorf("expected 1 finding, got %d", len(got))
	} else if got[0].ID != "TLS_TLS10_ENABLED" {
		t.Errorf("unexpected id %s", got[0].ID)
	}
	if got := r.Evaluate(&EvalContext{Protocols: &ProtocolSupport{TLS10: TriNo}}); len(got) != 0 {
		t.Errorf("expected 0 findings when TLS10=TriNo")
	}
	if got := r.Evaluate(&EvalContext{}); len(got) != 0 {
		t.Errorf("expected 0 findings when Protocols is nil")
	}
	_ = rep
}

func TestRuleTLS11Enabled(t *testing.T) {
	r := ruleTLS11Enabled{}
	if got := r.Evaluate(&EvalContext{Protocols: &ProtocolSupport{TLS11: TriYes}}); len(got) != 1 {
		t.Errorf("expected 1 finding, got %d", len(got))
	}
}

func TestRuleNoTLS12(t *testing.T) {
	r := ruleNoTLS12{}
	if got := r.Evaluate(&EvalContext{Protocols: &ProtocolSupport{TLS12: TriNo}}); len(got) != 1 {
		t.Errorf("expected 1 finding")
	}
	if got := r.Evaluate(&EvalContext{Protocols: &ProtocolSupport{TLS12: TriYes}}); len(got) != 0 {
		t.Errorf("expected 0 findings")
	}
}

func TestRuleNoTLS13(t *testing.T) {
	r := ruleNoTLS13{}
	if got := r.Evaluate(&EvalContext{Protocols: &ProtocolSupport{TLS13: TriNo}}); len(got) != 1 {
		t.Errorf("expected 1 finding")
	}
}

func TestRuleWeakCipher3DES(t *testing.T) {
	r := ruleWeakCipher3DES{}
	if got := r.Evaluate(&EvalContext{Ciphers: &CipherSuiteReport{Weak3DES: true}}); len(got) != 1 {
		t.Errorf("expected 1 finding")
	}
	if got := r.Evaluate(&EvalContext{Ciphers: &CipherSuiteReport{Weak3DES: false}}); len(got) != 0 {
		t.Errorf("expected 0 findings")
	}
}

func TestRuleWeakCipherCBCSHA1(t *testing.T) {
	r := ruleWeakCipherCBCSHA1{}
	if got := r.Evaluate(&EvalContext{Ciphers: &CipherSuiteReport{WeakCBCSHA1: true}}); len(got) != 1 {
		t.Errorf("expected 1 finding")
	}
}

func TestRuleNoForwardSecrecy(t *testing.T) {
	r := ruleNoForwardSecrecy{}
	if got := r.Evaluate(&EvalContext{Ciphers: &CipherSuiteReport{ForwardSecrecy: false}}); len(got) != 1 {
		t.Errorf("expected 1 finding when no FS")
	}
	if got := r.Evaluate(&EvalContext{Ciphers: &CipherSuiteReport{ForwardSecrecy: true}}); len(got) != 0 {
		t.Errorf("expected 0 findings when FS supported")
	}
}

func TestRuleHSTSMissing(t *testing.T) {
	r := ruleHSTSMissing{}
	if got := r.Evaluate(&EvalContext{HSTS: &HSTSReport{}}); len(got) != 1 {
		t.Errorf("expected 1 finding when no HSTS header")
	}
	if got := r.Evaluate(&EvalContext{HSTS: &HSTSReport{StrictTransportSecurity: "max-age=31536000"}}); len(got) != 0 {
		t.Errorf("expected 0 findings when HSTS present")
	}
}

func TestRuleHSTSShortMaxAge(t *testing.T) {
	r := ruleHSTSShortMaxAge{}
	if got := r.Evaluate(&EvalContext{HSTS: &HSTSReport{HSTSShortMaxAge: true}}); len(got) != 1 {
		t.Errorf("expected 1 finding")
	}
}

func TestRuleHSTSOnHTTP(t *testing.T) {
	r := ruleHSTSOnHTTP{}
	if got := r.Evaluate(&EvalContext{HSTS: &HSTSReport{HSTSOnHTTP: true}}); len(got) != 1 {
		t.Errorf("expected 1 finding")
	}
}

func TestRuleHTTPNoRedirect(t *testing.T) {
	r := ruleHTTPNoRedirect{}
	if got := r.Evaluate(&EvalContext{HSTS: &HSTSReport{HTTPSRedirect: false}}); len(got) != 1 {
		t.Errorf("expected 1 finding")
	}
	if got := r.Evaluate(&EvalContext{HSTS: &HSTSReport{HTTPSRedirect: true}}); len(got) != 0 {
		t.Errorf("expected 0 findings when redirect present")
	}
}

func TestRuleStartTLSNotOffered(t *testing.T) {
	r := ruleStartTLSNotOffered{}
	if got := r.Evaluate(&EvalContext{StartTLS: &StartTLSReport{UpgradeSucceeded: true}}); len(got) != 0 {
		t.Errorf("expected 0 findings when upgrade succeeded")
	}
	if got := r.Evaluate(&EvalContext{StartTLS: &StartTLSReport{UpgradeSucceeded: false, FailureReason: "smtp STARTTLS: server replied 502"}}); len(got) != 1 {
		t.Errorf("expected 1 finding when upgrade refused")
	}
	// TLS-handshake failure after a successful upgrade is NOT
	// flagged by this rule.
	if got := r.Evaluate(&EvalContext{StartTLS: &StartTLSReport{UpgradeSucceeded: true, FailureReason: "TLS handshake after STARTTLS: ..."}}); len(got) != 0 {
		t.Errorf("expected 0 findings for TLS-handshake failure post-upgrade")
	}
}

func TestAllRulesCoveredInDefaultRules(t *testing.T) {
	// Each rule declared in rules_active.go MUST appear in
	// DefaultRules. This test catches forgotten registrations.
	registered := map[string]bool{}
	for _, r := range DefaultRules() {
		registered[r.ID()] = true
	}
	expected := []string{
		"TLS_TLS10_ENABLED",
		"TLS_TLS11_ENABLED",
		"TLS_NO_TLS12",
		"TLS_NO_TLS13",
		"TLS_WEAK_CIPHER_3DES",
		"TLS_WEAK_CIPHER_CBC_SHA1",
		"TLS_NO_FORWARD_SECRECY",
		"TLS_HSTS_MISSING",
		"TLS_HSTS_SHORT_MAXAGE",
		"TLS_HSTS_ON_HTTP",
		"TLS_HTTP_NO_REDIRECT",
		"TLS_STARTTLS_NOT_OFFERED",
	}
	for _, id := range expected {
		if !registered[id] {
			t.Errorf("rule %s not registered in DefaultRules", id)
		}
	}
	_ = security.SafeTarget{}
	_ = ptrBool(true)
}
