package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/audit"
	"github.com/bornholm/netprobe-mcp/internal/probe"
	"github.com/bornholm/netprobe-mcp/internal/security"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// GRPCOptions mirrors probe.GRPCOptions with jsonschema tags so the
// SDK can publish the schema. Defined locally so future evolutions
// (extra knobs) don't churn probe.GRPCOptions.
type GRPCOptions = probe.GRPCOptions

// registerGRPCProbe wires the grpc_probe tool into the MCP server.
// The tool is exposed only when the GRPCProber dep was provided
// (i.e. when probes.grpc.enabled is true in the policy file).
func (s *Server) registerGRPCProbe() error {
	if s.grpcProber == nil || s.grpcProber.Prober == nil {
		return nil
	}
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:  "grpc_probe",
		Title: "Probe a gRPC server health",
		Description: "Send a single grpc.health.v1.Health/Check request to an " +
			"allow-listed target and report the health status (SERVING, " +
			"NOT_SERVING, UNKNOWN, SERVICE_UNKNOWN). Optional TLS wrapping " +
			"via use_tls=true.\n\n" +
			"Restricted to the standard Health Checking Protocol: the agent " +
			"cannot invoke arbitrary gRPC methods or expose server " +
			"reflection. Any service name passed in `service` is forwarded " +
			"verbatim to the server, which decides whether it is known.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			IdempotentHint:  true,
			OpenWorldHint:   boolPtr(true),
		},
	}, s.handleGRPCProbe)
	return nil
}

// handleGRPCProbe implements the standard pipeline:
// validate → authorise → execute → audit → summarise.
//
// The probe is intentionally shallow: one Health/Check request, one
// response, no retries. A flaky gRPC server shows up as Success=false
// in the structured output, not as a tool error (PLAN §13.14).
func (s *Server) handleGRPCProbe(ctx context.Context, req *mcp.CallToolRequest, in GRPCOptions) (*mcp.CallToolResult, probe.GRPCProbeResult, error) {
	sessionID := sessionIDFromCtx(ctx, req)
	start := time.Now()

	// Validate the port ourselves (the prober also checks, but
	// we want to short-circuit before any rate-limit budget is
	// burned on a malformed call).
	if in.Port < 0 || in.Port > 65535 {
		ev := &audit.Event{
			SessionID:  sessionID,
			Tool:       "grpc_probe",
			Decision:   "denied",
			Outcome:    audit.OutcomeDenied,
			DenyReason: fmt.Sprintf("invalid port %d", in.Port),
		}
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{
				Text: "grpc_probe REFUSED: " + ev.DenyReason,
			}},
		}
		return result, probe.GRPCProbeResult{}, MarkDenied(ev)
	}

	// Pick the effective port. We authorise against the *default*
	// port when the caller omitted one, then pass the same value
	// to the prober so the pin/unpin checks line up.
	effectivePort := uint16(in.Port)
	if effectivePort == 0 {
		effectivePort = s.grpcProber.DefaultPort
	}

	target, err := s.guard.Authorize(ctx, security.Request{
		Tool:      "grpc_probe",
		SessionID: sessionID,
		Scheme:    "grpc",
		Host:      in.Host,
		Port:      effectivePort,
		Purpose:   security.PurposeProbe,
	})
	if err != nil {
		ev := &audit.Event{
			SessionID:       sessionID,
			Tool:            "grpc_probe",
			Decision:        "denied",
			Outcome:         audit.OutcomeDenied,
			DenyReason:      security.PublicReason(err),
			RequestedTarget: fmt.Sprintf("%s:%d", in.Host, effectivePort),
		}
		s.recordDenial(ev, err)
		s.metrics.DenialsTotal.WithLabelValues("grpc_probe", string(denyCategory(err))).Inc()
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{
				Text: "grpc_probe REFUSED by policy: " + security.PublicReason(err),
			}},
		}
		denied := probe.GRPCProbeResult{
			Result: probe.Result{
				Probe:   "grpc_probe",
				Success: false,
				Error:   security.PublicReason(err),
				Target: probe.Target{
					Requested: fmt.Sprintf("%s:%d", in.Host, effectivePort),
					Hostname:  in.Host,
					Port:      effectivePort,
				},
			},
		}
		return result, denied, MarkDenied(ev)
	}
	defer target.Release()

	probeCtx, cancel := context.WithTimeout(ctx, s.grpcProber.DialTimeout)
	defer cancel()

	res, perr := s.grpcProber.Run(probeCtx, target, s.dialer, in)
	dur := time.Since(start)

	if perr != nil {
		s.recordInternal(req, sessionID, "grpc_probe", in.Host, perr)
		failed := probe.GRPCProbeResult{
			Result: probe.Result{
				Probe:      "grpc_probe",
				Success:    false,
				Error:      probe.SanitizeNetErr(perr),
				ErrorClass: "internal",
				Target: probe.Target{
					Requested:  fmt.Sprintf("%s:%d", in.Host, effectivePort),
					Hostname:   target.Hostname,
					ResolvedIP: target.IP.String(),
					Port:       effectivePort,
					Scheme:     "grpc",
				},
			},
		}
		failed.DurationMs = float64(dur.Microseconds()) / 1000.0
		failed.Timings.TotalMs = failed.DurationMs
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{
				Text: "grpc_probe internal error: " + probe.SanitizeNetErr(perr),
			}},
		}
		return result, failed, nil
	}

	if res == nil {
		failed := probe.GRPCProbeResult{
			Result: probe.Result{
				Probe:   "grpc_probe",
				Success: false,
				Error:   "nil result",
				Target: probe.Target{
					Requested:  fmt.Sprintf("%s:%d", in.Host, effectivePort),
					Hostname:   target.Hostname,
					ResolvedIP: target.IP.String(),
					Port:       effectivePort,
					Scheme:     "grpc",
				},
			},
		}
		failed.DurationMs = float64(dur.Microseconds()) / 1000.0
		failed.Timings.TotalMs = failed.DurationMs
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{
				Text: "grpc_probe internal error: nil result",
			}},
		}
		return result, failed, fmt.Errorf("nil result")
	}

	// Stamp the duration on the way out (the prober sets it too,
	// but we trust the wall-clock here so a slow rate-limit path
	// is captured).
	if res.DurationMs == 0 {
		res.DurationMs = float64(dur.Microseconds()) / 1000.0
	}

	// Build the agent-facing text. The TLS subject, when present,
	// is untrusted remote data — wrap it in <untrusted_remote_content>.
	text := summarizeGRPC(res)
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
			Tool:            "grpc_probe",
			Decision:        "allowed",
			Outcome:         outcome,
			MatchedRule:     target.MatchedRule,
			RequestedTarget: fmt.Sprintf("%s:%d", in.Host, effectivePort),
			ResolvedAddr:    target.IP.String(),
			ResolvedPort:    target.Port,
			DurationMs:      res.DurationMs,
		})
	}
	s.metrics.ProbesTotal.WithLabelValues("grpc_probe", outcome).Inc()
	s.metrics.ProbeDurationSecs.WithLabelValues("grpc_probe").Observe(res.DurationMs / 1000.0)

	return result, *res, nil
}

// summarizeGRPC produces a short, agent-readable summary. Mirrors
// the style of summarizeHTTP / summarizeTCP / summarizeICMP so the
// agent has a consistent shape across probes.
func summarizeGRPC(r *probe.GRPCProbeResult) string {
	if r == nil {
		return "grpc_probe: no result"
	}
	if !r.Success {
		msg := fmt.Sprintf("grpc_probe FAILED for %s:%d (%s) - %s",
			r.Target.Hostname, r.Target.Port,
			grpcStatusLabel(r.GRPC),
			r.Error)
		return msg
	}
	var b strings.Builder
	fmt.Fprintf(&b, "grpc_probe OK %s:%d status=%s in %.0fms",
		r.Target.Hostname, r.Target.Port,
		r.GRPC.HealthStatus, r.DurationMs)
	if r.GRPC.HTTPStatus != 0 {
		fmt.Fprintf(&b, " http=%d", r.GRPC.HTTPStatus)
	}
	if r.GRPC.TLS != nil && r.GRPC.TLS.PeerSubject != "" {
		source := fmt.Sprintf("grpc+tls://%s:%d", r.Target.Hostname, r.Target.Port)
		fmt.Fprintf(&b, "\ntls_peer=%s", probe.WrapUntrustedContent(r.GRPC.TLS.PeerSubject, source))
	}
	return b.String()
}

// grpcStatusLabel is the short, single-token summary used in error
// messages. Keeps the agent's reasoning loop free of long strings.
func grpcStatusLabel(g *probe.GRPCResult) string {
	if g == nil {
		return "no_result"
	}
	if g.HealthStatus != "" {
		return g.HealthStatus
	}
	return "unknown"
}

// Ensure errors.As compiles even if a future refactor stops using it
// directly — keeps staticcheck happy across handler files.
var _ = errors.As
