package mcpserver

import (
	"strings"
	"testing"

	"github.com/bornholm/netprobe-mcp/internal/audit"
)

// TestAuditEventErr_ErrorSurfacesReason is a regression test for a bug
// where the MCP SDK overwrote CallToolResult.Content with err.Error()
// when a handler returned MarkDenied. The audit-event error had an
// empty Error() method, so the LLM saw an empty text body and could
// not tell why its call had been refused.
func TestAuditEventErr_ErrorSurfacesReason(t *testing.T) {
	ev := &audit.Event{
		Decision:   "denied",
		Outcome:    audit.OutcomeDenied,
		DenyReason: "host \"evil.example.com\" is not in the allow-list",
	}
	err := MarkDenied(ev)
	if err == nil {
		t.Fatal("MarkDenied returned nil")
	}
	msg := err.Error()
	if msg == "" {
		t.Fatal("MarkDenied.Error() returned empty string; LLM would see empty error text")
	}
	if !strings.Contains(msg, "evil.example.com") {
		t.Errorf("Error() = %q, want it to contain the deny reason", msg)
	}

	// MarkInternal without a DenyReason should still produce useful text.
	ev2 := &audit.Event{Decision: "allowed", Outcome: audit.OutcomeInternal}
	err2 := MarkInternal(ev2)
	if err2 == nil || err2.Error() == "" {
		t.Errorf("MarkInternal.Error() = %q, want non-empty", err2)
	}
}

// TestMarkDenied_NilEvent is a guard for the nil branch.
func TestMarkDenied_NilEvent(t *testing.T) {
	if err := MarkDenied(nil); err != nil {
		t.Errorf("MarkDenied(nil) = %v, want nil", err)
	}
	if err := MarkInternal(nil); err != nil {
		t.Errorf("MarkInternal(nil) = %v, want nil", err)
	}
}
