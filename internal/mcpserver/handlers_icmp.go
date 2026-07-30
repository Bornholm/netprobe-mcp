// Package mcpserver exposes the icmp_probe tool. The tool is
// registered only when the runtime detected a usable ICMP mode at
// boot; if neither unprivileged nor raw sockets are available the
// tool is not exposed at all (PLAN §7.4 / §9.3).
package mcpserver

import (
	"context"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/audit"
	"github.com/bornholm/netprobe-mcp/internal/probe"
	"github.com/bornholm/netprobe-mcp/internal/probe/icmp"
	"github.com/bornholm/netprobe-mcp/internal/security"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ICMPDep bundles everything the icmp_probe handler needs.
type ICMPDep struct {
	Prober      *icmp.Prober
	DialTimeout time.Duration
}

// registerICMPProbe wires the icmp_probe tool into the MCP server.
// The tool is exposed only when the prober's mode is not "unavailable"
// — the boot-time capability check documented in PLAN.md §7.4 is the
// source of truth.
func (s *Server) registerICMPProbe() error {
	if s.icmpProber == nil || s.icmpProber.Prober == nil {
		return nil
	}
	if s.icmpProber.Prober.Mode() == icmp.ModeUnavailable {
		s.logger.Warn("icmp_probe not registered: no ICMP capability at boot",
			"hint", "grant CAP_NET_RAW or configure net.ipv4.ping_group_range")
		return nil
	}
	mode := string(s.icmpProber.Prober.Mode())
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:  "icmp_probe",
		Title: "Probe a host with ICMP echo",
		Description: "Send ICMP echo requests (" + mode + ") to an allow-listed host and report " +
			"packets sent, replies received, packet loss and round-trip statistics. " +
			"Mirrors the icmp module of Prometheus blackbox_exporter.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			IdempotentHint:  false,
			OpenWorldHint:   boolPtr(true),
		},
	}, s.handleICMPProbe)
	return nil
}

// handleICMPProbe implements the agent-facing handler. The pipeline
// matches every other handler: validate → authorise → execute →
// audit.
func (s *Server) handleICMPProbe(ctx context.Context, req *mcp.CallToolRequest, in icmp.Options) (*mcp.CallToolResult, icmp.Result, error) {
	sessionID := sessionIDFromCtx(ctx, req)
	start := time.Now()

	if err := s.icmpProber.Prober.Validate(&in); err != nil {
		ev := &audit.Event{
			SessionID:  sessionID,
			Tool:       "icmp_probe",
			Decision:   "denied",
			Outcome:    audit.OutcomeDenied,
			DenyReason: err.Error(),
		}
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: "icmp_probe REFUSED: " + err.Error()}},
		}
		denied := &icmp.Result{
			Result: probe.Result{
				Probe: "icmp_probe", Success: false, Error: err.Error(), ErrorClass: "validation",
			},
		}
		return result, *denied, MarkDenied(ev)
	}

	target, err := s.guard.Authorize(ctx, security.Request{
		Tool:      "icmp_probe",
		SessionID: sessionID,
		Scheme:    "icmp",
		Host:      in.Host,
		Port:      0,
		Purpose:   security.PurposeICMPProbe,
	})
	if err != nil {
		ev := &audit.Event{
			SessionID:       sessionID,
			Tool:            "icmp_probe",
			Decision:        "denied",
			Outcome:         audit.OutcomeDenied,
			DenyReason:      security.PublicReason(err),
			RequestedTarget: in.Host,
		}
		s.recordDenial(ev, err)
		s.metrics.DenialsTotal.WithLabelValues("icmp_probe", string(denyCategory(err))).Inc()
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: "icmp_probe REFUSED by policy: " + security.PublicReason(err)}},
		}
		denied := &icmp.Result{
			Result: probe.Result{
				Probe: "icmp_probe", Success: false, Error: security.PublicReason(err), ErrorClass: "policy",
			},
		}
		return result, *denied, MarkDenied(ev)
	}
	defer target.Release()

	res, err := s.icmpProber.Prober.Run(ctx, target, in)
	if err != nil {
		ev := &audit.Event{
			SessionID:       sessionID,
			Tool:            "icmp_probe",
			Decision:        "allowed",
			Outcome:         audit.OutcomeInternal,
			DenyReason:      err.Error(),
			RequestedTarget: in.Host,
		}
		s.recordInternal(req, sessionID, "icmp_probe", in.Host, err)
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: "icmp_probe internal error: " + sanitizeTLSDiagErr(err)}},
		}
		failed := &icmp.Result{
			Result: probe.Result{
				Probe: "icmp_probe", Success: false, Error: err.Error(), ErrorClass: "internal",
			},
		}
		return result, *failed, MarkInternal(ev)
	}
	if res == nil {
		res = &icmp.Result{
			Result: probe.Result{Probe: "icmp_probe", Success: false, Error: "nil result"},
		}
	}

	outcome := audit.OutcomeSuccess
	if !res.Success {
		outcome = audit.OutcomeProbeFailure
	}
	if s.audit != nil {
		s.audit.Emit(&audit.Event{
			SessionID:       sessionID,
			Tool:            "icmp_probe",
			Decision:        "allowed",
			Outcome:         outcome,
			RequestedTarget: in.Host,
			ResolvedAddr:    res.Target.ResolvedIP,
			DurationMs:      float64(time.Since(start).Microseconds()) / 1000.0,
		})
	}
	s.metrics.ProbesTotal.WithLabelValues("icmp_probe", outcome).Inc()
	s.metrics.ProbeDurationSecs.WithLabelValues("icmp_probe").Observe(res.DurationMs / 1000.0)

	text := summarizeICMP(res)
	result := &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
	return result, *res, nil
}

// summarizeICMP produces a short, agent-readable summary.
func summarizeICMP(r *icmp.Result) string {
	if r == nil {
		return "icmp_probe: no result"
	}
	return formatICMPSummary(r)
}

// formatICMPSummary is separated so it can be unit-tested without
// touching the network.
func formatICMPSummary(r *icmp.Result) string {
	if r == nil {
		return "icmp_probe: no result"
	}
	if !r.Success {
		return "icmp_probe FAILED " + r.Target.Hostname + " - 0 replies of " +
			intStr(r.PacketsSent) + " sent"
	}
	return "icmp_probe OK " + r.Target.Hostname + " -> " + r.Target.ResolvedIP +
		" sent=" + intStr(r.PacketsSent) + " recv=" + intStr(r.PacketsReceived) +
		" loss=" + floatStr(r.PacketLossPct) + "%" +
		" min=" + floatStr(r.MinRTTMs) + "ms" +
		" avg=" + floatStr(r.AvgRTTMs) + "ms" +
		" max=" + floatStr(r.MaxRTTMs) + "ms" +
		" mode=" + r.Mode
}

func intStr(n int) string       { return fmtInt(n) }
func floatStr(f float64) string { return fmtFloat(f) }

func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	// Minimal integer-to-string to avoid pulling fmt in helpers
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func fmtFloat(f float64) string {
	// Two-decimal truncation. Good enough for an agent-facing line.
	if f == 0 {
		return "0.00"
	}
	intPart := int(f)
	fracPart := int((f - float64(intPart)) * 100)
	if fracPart < 0 {
		fracPart = -fracPart
	}
	s := fmtInt(intPart) + "." + twoDigits(fracPart)
	return s
}

func twoDigits(n int) string {
	if n < 10 {
		return "0" + fmtInt(n)
	}
	return fmtInt(n)
}
