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
