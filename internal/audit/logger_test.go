package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// safeBuf is a goroutine-safe buffer used as the audit writer in
// tests. The Logger writes concurrently from a goroutine so the
// embedded buffer must be guarded.
type safeBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestEvent_OutboundURLsLogged(t *testing.T) {
	buf := &safeBuf{}
	l, err := New(Config{
		Format: "json",
		Writer: buf,
		Level:  "info",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	ev := &Event{
		Tool:     "tls_diagnose",
		Decision: "allowed",
		Outcome:  OutcomeSuccess,
		OutboundURLs: []OutboundURLEvent{
			{URL: "http://aia.example.com/ca.crt", Purpose: "aia_fetch", Outcome: "denied", Reason: "policy"},
			{URL: "http://ocsp.example.com/", Purpose: "ocsp_query", Outcome: "success", BytesRead: 472},
		},
		Findings: []string{"TLS_HOSTNAME_MISMATCH", "TLS_CHAIN_MISSING_INTERMEDIATE"},
	}
	l.Emit(ev)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), "outbound_urls") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	l.Close()
	out := buf.String()
	if !strings.Contains(out, "aia_fetch") {
		t.Errorf("audit log missing aia_fetch purpose: %s", out)
	}
	if !strings.Contains(out, "ocsp_query") {
		t.Errorf("audit log missing ocsp_query purpose: %s", out)
	}
	if !strings.Contains(out, "TLS_HOSTNAME_MISMATCH") {
		t.Errorf("audit log missing finding ID: %s", out)
	}

	// Round-trip JSON to make sure the Event serializes cleanly
	// with the new fields. Regression check against accidental
	// field omission in MarshalJSON.
	raw, mErr := json.Marshal(ev)
	if mErr != nil {
		t.Fatalf("marshal: %v", mErr)
	}
	var roundtrip map[string]any
	if err := json.Unmarshal(raw, &roundtrip); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := roundtrip["outbound_urls"]; !ok {
		t.Errorf("outbound_urls missing from JSON: %s", string(raw))
	}
	if _, ok := roundtrip["findings"]; !ok {
		t.Errorf("findings missing from JSON: %s", string(raw))
	}
}

func TestEvent_DeniedSyncWrite(t *testing.T) {
	buf := &safeBuf{}
	l, err := New(Config{
		Format: "json",
		Writer: buf,
		Level:  "info",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Denials are written synchronously; the goroutine need not run.
	l.Emit(&Event{
		Tool:       "tls_diagnose",
		Decision:   "denied",
		Outcome:    OutcomeDenied,
		DenyReason: "test denial",
	})
	if !strings.Contains(buf.String(), "test denial") {
		t.Errorf("synchronous denial write failed: %s", buf.String())
	}
	_ = context.Background()
}

// TestSanitizeTarget_ScrubsInternalIPs is the regression test for
// PLAN §11.1: the audit log MUST NOT contain internal addresses
// even when LogTargets is true and even for denied requests. The
// redactor must replace every IPv4/IPv6 from a reserved range with
// the sentinel [internal-ip].
func TestSanitizeTarget_ScrubsInternalIPs(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"loopback v4", "tcp://127.0.0.1:80", "[internal-ip]"},
		{"loopback v4 in URL", "http://127.0.0.1/admin", "[internal-ip]"},
		{"private 10/8", "10.0.0.5", "[internal-ip]"},
		{"private 172.16/12", "172.16.0.1", "[internal-ip]"},
		{"private 192.168/16", "192.168.1.1", "[internal-ip]"},
		{"CGNAT 100.64/10", "100.64.0.1", "[internal-ip]"},
		{"link-local metadata", "169.254.169.254", "[internal-ip]"},
		{"ipv6 loopback", "::1", "[internal-ip]"},
		{"ipv6 ULA", "fc00::1", "[internal-ip]"},
		{"ipv6 link-local", "fe80::1", "[internal-ip]"},
		{"ipv6 v4-mapped", "::ffff:10.0.0.1", "[internal-ip]"},
		{"public 8.8.8.8 preserved", "8.8.8.8", "8.8.8.8"},
		{"public 1.1.1.1 preserved", "1.1.1.1:443", "1.1.1.1:443"},
		{"empty preserved", "", ""},
		{"truncation", strings.Repeat("a", 250), strings.Repeat("a", 200) + "\u2026"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeTarget(tc.in)
			if got != tc.want {
				t.Errorf("sanitizeTarget(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestEvent_OutboundURLScrubbed verifies that an outbound URL
// pointing at an internal address is scrubbed before emission.
// The URL must remain legible (scheme + path) — only the host
// component is replaced.
func TestEvent_OutboundURLScrubbed(t *testing.T) {
	buf := &safeBuf{}
	l, err := New(Config{
		Format: "json",
		Writer: buf,
		Level:  "info",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	l.Emit(&Event{
		Tool:     "tls_diagnose",
		Decision: "allowed",
		Outcome:  OutcomeSuccess,
		OutboundURLs: []OutboundURLEvent{
			{URL: "http://10.255.255.1/ca.crt", Purpose: "aia_fetch", Outcome: "success"},
		},
	})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), "outbound_urls") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	l.Close()
	out := buf.String()
	if strings.Contains(out, "10.255.255.1") {
		t.Errorf("internal IP leaked into audit log: %s", out)
	}
	if !strings.Contains(out, "[internal-ip]") {
		t.Errorf("expected [internal-ip] sentinel in audit log: %s", out)
	}
}
