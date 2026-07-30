package mcpserver

import (
	"context"
	"errors"

	"github.com/bornholm/netprobe-mcp/internal/audit"
)

// auditHintKey is the unexported key under which an *audit.Event can be
// attached to a context by a handler that wants the middleware to emit it
// verbatim instead of synthesising a generic event.
type auditHintKey struct{}

// auditHint is the value carrier; using a struct wrapper avoids collision
// with any future context-key type and keeps a typed accessor.
type auditHint struct{ Event *audit.Event }

// WithAuditHint attaches an audit event to ctx. When the MCP middleware
// observes such an event after the handler runs, it emits it as-is and does
// NOT generate a generic success/denied event on top of it.
func WithAuditHint(ctx context.Context, ev *audit.Event) context.Context {
	if ev == nil {
		return ctx
	}
	return context.WithValue(ctx, auditHintKey{}, &auditHint{Event: ev})
}

// AuditHintFromContext returns the event attached to ctx, if any.
func AuditHintFromContext(ctx context.Context) (*audit.Event, bool) {
	h, ok := ctx.Value(auditHintKey{}).(*auditHint)
	if !ok || h == nil {
		return nil, false
	}
	return h.Event, true
}

// auditEventErr is a sentinel error that carries an audit event through the
// handler return path. The MCP handler signature does not let us return a
// fresh context, so we smuggle the event out via the error and the audit
// middleware unwraps it. The error's Error() returns an empty string so it
// does not surface in client-facing messages.
type auditEventErr struct {
	Event *audit.Event
}

func (e *auditEventErr) Error() string { return "" }

// MarkDenied returns an audit-event-bearing error. Handlers should return it
// as their third return value when they have refused a call by policy.
// The audit middleware will emit the event; the SDK ignores the empty Error
// message because the handler already produced a CallToolResult.
func MarkDenied(ev *audit.Event) error {
	if ev == nil {
		return nil
	}
	ev.Decision = "denied"
	if ev.Outcome == "" {
		ev.Outcome = audit.OutcomeDenied
	}
	return &auditEventErr{Event: ev}
}

// MarkInternal signals an internal failure (post-policy).
func MarkInternal(ev *audit.Event) error {
	if ev == nil {
		return nil
	}
	if ev.Outcome == "" {
		ev.Outcome = audit.OutcomeInternal
	}
	return &auditEventErr{Event: ev}
}

// unwrapAuditEvent extracts an audit event from an error chain.
func unwrapAuditEvent(err error) (*audit.Event, bool) {
	var ae *auditEventErr
	if errors.As(err, &ae) {
		return ae.Event, true
	}
	return nil, false
}
