package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/audit"
	"github.com/bornholm/netprobe-mcp/internal/probe"
	"github.com/bornholm/netprobe-mcp/internal/security"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (s *Server) registerTools() error {
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "probe_policy",
		Title:       "Show probing policy",
		Description: "Return the active security policy: which target patterns are allowed, which ports and schemes are permitted, current rate limits, and which probe types are enabled. Call this first to understand what is possible before attempting any probe.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:   true,
			IdempotentHint: true,
			OpenWorldHint:  boolPtr(false),
		},
	}, s.handleProbePolicy)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "probe_check_target",
		Title:       "Check whether a target is allowed",
		Description: "Dry-run the authorisation pipeline for a target without sending any network traffic. Returns whether the target is permitted, which rule matched, and the reason for any denial.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:  true,
			OpenWorldHint: boolPtr(false),
		},
	}, s.handleCheckTarget)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "tcp_probe",
		Title:       "Probe a TCP endpoint",
		Description: "Open a single TCP connection to an allow-listed target and optionally read a sanitized banner or run a hard-coded named dialogue. Available dialogues: smtp_banner, imap_capability, pop3_banner, mysql_handshake. Per PLAN §7.3 the agent cannot send arbitrary bytes — only the bytes defined in the chosen dialogue cross the wire.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			IdempotentHint:  false,
			OpenWorldHint:   boolPtr(true),
		},
	}, s.handleTCPProbe)

	return nil
}

// --- Tool 1: probe_policy ---

type PolicyOut struct {
	AllowCount  int      `json:"allow_rules"`
	DenyCount   int      `json:"deny_rules"`
	Probes      []string `json:"probes_enabled"`
	RPSGlobal   float64  `json:"rps_global"`
	BurstGlobal int      `json:"burst_global"`
	MaxConc     int      `json:"max_concurrent"`
	IPFamily    string   `json:"ip_family"`
}

func (s *Server) handleProbePolicy(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, PolicyOut, error) {
	out := PolicyOut{}
	if s.cfg != nil {
		out.AllowCount = len(s.cfg.Security.Targets.Allow)
		out.DenyCount = len(s.cfg.Security.Targets.Deny)
		out.RPSGlobal = s.cfg.Limits.Global.RPS
		out.BurstGlobal = s.cfg.Limits.Global.Burst
		out.MaxConc = s.cfg.Limits.MaxConcurrentProbes
		ipFamily := "ipv4"
		if s.cfg.Security.Network.IPv6Allowed() {
			if s.cfg.Security.Network.IPv4Allowed() {
				ipFamily = "dual"
			} else {
				ipFamily = "ipv6"
			}
		}
		out.IPFamily = ipFamily
	}
	out.Probes = []string{}
	if s.tcpProber != nil {
		out.Probes = append(out.Probes, "tcp_probe")
	}
	if s.httpProber != nil {
		out.Probes = append(out.Probes, "http_probe")
	}
	if s.dnsProber != nil {
		out.Probes = append(out.Probes, "dns_probe")
	}
	if s.icmpProber != nil {
		out.Probes = append(out.Probes, "icmp_probe")
	}
	if s.grpcProber != nil {
		out.Probes = append(out.Probes, "grpc_probe")
	}
	if s.tlsDiagnose != nil {
		out.Probes = append(out.Probes, "tls_diagnose")
	}
	return nil, out, nil
}

// --- Tool 2: probe_check_target ---

type CheckTargetIn struct {
	Host string `json:"host" jsonschema:"hostname or IP literal"`
	Port int    `json:"port,omitempty" jsonschema:"TCP port (1-65535)"`
	Tool string `json:"tool,omitempty" jsonschema:"probe type to test (defaults to tcp_probe)"`
}

type CheckTargetOut struct {
	Allowed     bool   `json:"allowed"`
	Host        string `json:"host"`
	Port        uint16 `json:"port"`
	Tool        string `json:"tool"`
	Reason      string `json:"reason,omitempty"`
	Category    string `json:"category,omitempty"`
	Hint        string `json:"hint,omitempty"`
	MatchedRule string `json:"matched_rule,omitempty"`
}

func (s *Server) handleCheckTarget(ctx context.Context, req *mcp.CallToolRequest, in CheckTargetIn) (*mcp.CallToolResult, CheckTargetOut, error) {
	tool := in.Tool
	if tool == "" {
		tool = "tcp_probe"
	}
	if in.Port == 0 {
		in.Port = 80
	}
	sessionID := sessionIDFromCtx(ctx, req)

	target, err := s.guard.Authorize(ctx, security.Request{
		Tool:      tool,
		SessionID: sessionID,
		Scheme:    "tcp",
		Host:      in.Host,
		Port:      uint16(in.Port),
		Purpose:   security.PurposeMeta,
	})
	out := CheckTargetOut{
		Host: in.Host,
		Port: uint16(in.Port),
		Tool: tool,
	}
	if err != nil {
		var de *security.DenyError
		if errors.As(err, &de) {
			out.Reason = de.Reason
			out.Category = string(de.Category)
			out.Hint = de.Hint
		} else {
			out.Reason = err.Error()
		}
		ev := &audit.Event{
			SessionID:       sessionID,
			Tool:            "probe_check_target",
			RequestedTarget: fmt.Sprintf("%s:%d", in.Host, in.Port),
		}
		s.recordDenial(ev, err)
		s.metrics.DenialsTotal.WithLabelValues("probe_check_target", string(denyCategory(err))).Inc()
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: security.PublicReason(err)}},
		}
		return result, out, MarkDenied(ev)
	}
	target.Release()
	out.Allowed = true
	out.MatchedRule = target.MatchedRule
	s.metrics.ProbesTotal.WithLabelValues("probe_check_target", "allowed").Inc()
	return nil, out, nil
}

// --- Tool 3: tcp_probe ---

type TCPProbeIn = probe.TCPOptions

type TCPProbeOut = probe.Result

func (s *Server) handleTCPProbe(ctx context.Context, req *mcp.CallToolRequest, in TCPProbeIn) (*mcp.CallToolResult, TCPProbeOut, error) {
	sessionID := sessionIDFromCtx(ctx, req)
	port := uint16(in.Port)
	if port == 0 {
		port = 80
	}

	start := time.Now()
	target, err := s.guard.Authorize(ctx, security.Request{
		Tool:      "tcp_probe",
		SessionID: sessionID,
		Scheme:    "tcp",
		Host:      in.Host,
		Port:      port,
		Purpose:   security.PurposeProbe,
	})
	if err != nil {
		ev := &audit.Event{
			SessionID:       sessionID,
			Tool:            "tcp_probe",
			RequestedTarget: fmt.Sprintf("%s:%d", in.Host, port),
		}
		s.recordDenial(ev, err)
		s.metrics.DenialsTotal.WithLabelValues("tcp_probe", string(denyCategory(err))).Inc()
		denied := &probe.Result{
			Probe:   "tcp_probe",
			Success: false,
			Error:   security.PublicReason(err),
			Target: probe.Target{
				Requested: fmt.Sprintf("%s:%d", in.Host, port),
				Hostname:  in.Host,
				Port:      port,
			},
		}
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: "tcp_probe REFUSED by policy: " + security.PublicReason(err)}},
		}
		return result, *denied, MarkDenied(ev)
	}

	probeCtx, cancel := context.WithTimeout(ctx, s.tcpProber.DialTimeout)
	defer cancel()

	res, perr := s.tcpProber.Prober.Run(probeCtx, target, s.dialer, in)
	target.Release()

	dur := time.Since(start)
	if res != nil {
		res.DurationMs = float64(dur.Microseconds()) / 1000.0
	}
	if perr != nil {
		s.recordInternal(req, sessionID, "tcp_probe", in.Host, perr)
		failed := &probe.Result{
			Probe:   "tcp_probe",
			Success: false,
			Error:   probe.SanitizeNetErr(perr),
			Target: probe.Target{
				Requested: fmt.Sprintf("%s:%d", in.Host, port),
				Hostname:  in.Host,
				Port:      port,
			},
		}
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: "tcp_probe internal error: " + probe.SanitizeNetErr(perr)}},
		}
		return result, *failed, nil
	}
	if res == nil {
		failed := &probe.Result{
			Probe: "tcp_probe", Success: false, Error: "nil result",
			Target: probe.Target{
				Requested: fmt.Sprintf("%s:%d", in.Host, port),
				Hostname:  in.Host,
				Port:      port,
			},
		}
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: "tcp_probe internal error: nil result"}},
		}
		return result, *failed, fmt.Errorf("nil result")
	}

	// Build the agent-facing text. The probe text is a summary, the structured
	// result is the source of truth.
	text := summarizeTCP(res)
	result := &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}

	outcome := audit.OutcomeSuccess
	if !res.Success {
		outcome = audit.OutcomeProbeFailure
	}
	if s.audit != nil {
		s.audit.Emit(&audit.Event{
			SessionID:       sessionID,
			Tool:            "tcp_probe",
			Decision:        "allowed",
			Outcome:         outcome,
			MatchedRule:     target.MatchedRule,
			RequestedTarget: fmt.Sprintf("%s:%d", in.Host, port),
			ResolvedAddr:    target.IP.String(),
			ResolvedPort:    target.Port,
			DurationMs:      res.DurationMs,
		})
	}
	s.metrics.ProbesTotal.WithLabelValues("tcp_probe", outcome).Inc()
	s.metrics.ProbeDurationSecs.WithLabelValues("tcp_probe").Observe(res.DurationMs / 1000.0)

	return result, *res, nil
}

// sessionIDFromCtx retrieves the session ID from the MCP session attached
// to the request.
func sessionIDFromCtx(_ context.Context, req *mcp.CallToolRequest) string {
	if req == nil {
		return "stdio-local"
	}
	if sess := req.Session; sess != nil {
		if id := sess.ID(); id != "" {
			return id
		}
	}
	return "stdio-local"
}

// recordDenial completes the audit event built by the caller and forwards it
// to the logger. Refusals are written synchronously so they cannot be lost.
func (s *Server) recordDenial(ev *audit.Event, err error) {
	if s.audit == nil || ev == nil {
		return
	}
	ev.Decision = "denied"
	ev.Outcome = audit.OutcomeDenied
	ev.DenyReason = security.PublicReason(err)
	s.audit.Emit(ev)
}

// recordInternal emits an audit event for an internal error.
func (s *Server) recordInternal(req *mcp.CallToolRequest, sessionID, tool, host string, err error) {
	if s.audit == nil {
		return
	}
	s.audit.Emit(&audit.Event{
		SessionID:       sessionID,
		Tool:            tool,
		Decision:        "allowed",
		Outcome:         audit.OutcomeInternal,
		DenyReason:      err.Error(),
		RequestedTarget: host,
	})
	s.logger.Error("internal probe error", slog.String("tool", tool), slog.Any("err", err))
}

func denyCategory(err error) string {
	var de *security.DenyError
	if errors.As(err, &de) {
		return string(de.Category)
	}
	return "unknown"
}

func boolPtr(b bool) *bool { return &b }

// summarizeTCP produces a short, human-readable summary the agent can read
// before parsing the structured output. The banner — which is content
// served by the target — is wrapped in <untrusted_remote_content>
// markers so the model treats it as opaque data, never as instructions.
// See PLAN.md §7.2 and §13.5.
func summarizeTCP(r *probe.Result) string {
	if !r.Success {
		return fmt.Sprintf("tcp_probe FAILED for %s:%d (%s) - %s",
			r.Target.Hostname, r.Target.Port, r.ErrorClass, r.Error)
	}
	b := fmt.Sprintf("tcp_probe OK %s:%d -> %s in %.0fms",
		r.Target.Hostname, r.Target.Port, r.Target.ResolvedIP, r.DurationMs)
	if r.TCP != nil && r.TCP.Banner != "" {
		source := fmt.Sprintf("tcp://%s:%d", r.Target.Hostname, r.Target.Port)
		b += "\n" + probe.WrapUntrustedContent(r.TCP.Banner, source)
	}
	return b
}
